;; TODO: this code needs some serious cleaning up and modularizing
(require xml net/url)
(date-display-format 'rfc2822)

;; Structs and helpers
(struct result (service-id notaries))
(struct notary (server fingerprints signature error))
(struct signature (value type))
(struct fingerprint (value timestamps))
(struct timestamp (beg end))
; The notary struct holds the consulted server's struct, plus
; either the fingerprints retrieved or the error occurred.
(struct server (address port type pub-key))
(struct service-id (address port type))

(define (service-id->string service-id)
    (list->string
        (list service-id-address ":" service-id-port "," service-id-type)))

(define (server->host server)
    (let ([address (server-address server)]
          [port (server-port server)])
        (string-append "http://" address ":" port "/")))

(define (xml-notary-reply->struct xexpr server)
    (define (xml-timestamp->struct Timestamp)
        (let ([beg (cadr (cadadr Timestamp))]
              [end (car  (cdaadr Timestamp))])
            (timestamp beg end)))
    (define (xml-key->struct key)
        (let* ([fingerprint-string (car (cdaadr key))]
               [xml-timestamps (cddr key)]
               [timestamps (map xml-timestamp->struct xml-timestamps)])
             (fingerprint fingerprint-string timestamps)))
    (define (xml-sig->struct sig)
        (let* ([value (cadar sig)]
               [type (cadadr sig)])
            (signature value type)))
    (let* ([clean-data (clean-results xexpr)]
           [xml-sig (car clean-data)]
           [sig (xml-sig->struct xml-sig)]
           [xml-fingerprints (cdr clean-data)]
           [fingerprints (map xml-key->struct xml-fingerprints)])
        (notary server fingerprints sig nil)))

; "remove" doesn't seem to work here
(define (clean-results xml)
    (define (clean-one-level list)
        (filter
            (lambda (line)
                (and (not (equal? line "\n"))
                     (not (equal? line "\n\t"))))
            list))
    (map clean-one-level (cdr (clean-one-level xml))))


;; Printing
(define (pretty-print-timestamps timestamps)
    (for-each
        (lambda (timestamp)
            (let ([num-beg (string->number (timestamp-beg timestamp))]
                  [num-end (string->number (timestamp-end timestamp))])
                (printf "start: ~a - ~a\n"
                        (timestamp-beg timestamp)
                        (date->string (seconds->date num-beg) #t))
                (printf "end:   ~a - ~a\n" 
                        (timestamp-end timestamp)
                        (date->string (seconds->date num-end) #t))))
        timestamps))

(define (pretty-print-fingerprints fingerprints)
    (for-each
        (lambda (fingerprint)
            (printf "key:   ~a\n" (fingerprint-value fingerprint))
            (pretty-print-timestamps (fingerprint-timestamps fingerprint))
            (newline))
        fingerprints))

(define (pretty-print-notaries notaries)
    (for-each
        (lambda (notary)
            (printf "***** probes from server ~a (~a) *****\n"
                (server-address (notary-server notary))
                (server-type    (notary-server notary)))
            (if (notary-response-ok? notary)
                (pretty-print-fingerprints (notary-fingerprints notary))
                (printf "error: ~a\n\n" (notary-error notary))))
        notaries))

(define (pretty-print results)
    (for-each
        (lambda (result)
            (pretty-print-notaries (result-notaries result)))
        results))


;; Scanning
(define (make-query address port service-type)
    (string-append "?host=" address "&port=" port "&service_type=" service-type))

(define (verify-result-signature result)
    #t)

(define (notary-response-ok? notary)
    (null? (notary-error notary)))

(define (error-result reason)
    (notary nil nil nil reason))

(define (scan address port service-type server)
    (let* ([server-host (server->host server)]
           [query (make-query address port service-type)]
           [url-string (string-append server-host query)]
           [url-struct (string->url url-string)]
           [io-port (get-pure-port url-struct)]
           [xml (read-xml io-port)]
           [result (xml->xexpr (document-element xml))]
           [parsed-result (xml-notary-reply->struct result server)])
        (if (verify-result-signature parsed-result)
            parsed-result
            (error-result "signature check failed"))))


;; Interface
(define (scan-client server-list result-list)
    (define (server-already-added? server) (member server server-list))
    (define (result-already-known? result) (member result result-list))

    (define (add-server server)
        (scan-client
            (if (server-already-added? server)
                server-list
                (cons server server-list))
            results))
    (define (add-result result)
        (scan-client
            server-list
            (if (result-already-known? result)
                result-list
                (cons result result-list))))
    
    (define (handle-scan address port service-type)
        (add-result
            (result
                (service-id address port service-type)
                (map (lambda (server) (scan address port service-type server))
                     server-list))))

    (define (dispatch m)
        (case m
            ('add-server (lambda args (add-server (apply server args))))
            ('scan       (lambda args (apply handle-scan args)))
            ('pretty-print (pretty-print result-list))
            ('server-list server-list)
            ('result-list result-list)))
    dispatch)
