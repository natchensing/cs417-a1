#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h> /* Basic Input/Output streams */
#include <openssl/err.h> /* errors */
#include <openssl/ssl.h> /* core library */
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>

#include <pthread.h>

#define BUFFER_SIZE 1024
#define DATE_LEN 128


void report_and_exit(const char* msg) {
  perror(msg);
  ERR_print_errors_fp(stderr);
  exit(-1);
}

void init_ssl() {
  SSL_load_error_strings();
  SSL_library_init();
}

void cleanup(SSL_CTX* ctx, BIO* bio) {
  SSL_CTX_free(ctx);
  BIO_free_all(bio);
}

void *read_user_input(void *arg) {
  SSL *ssl = arg;

  char buf[BUFFER_SIZE];
  size_t n;
  while (fgets(buf, sizeof(buf) - 1, stdin)) {
    /* Most text-based protocols use CRLF for line-termination. This
       code replaced a LF with a CRLF. */
    n = strlen(buf);
    if (buf[n-1] == '\n' && (n == 1 || buf[n-2] != '\r'))
      strcpy(&buf[n-1], "\r\n");
    
    /* TODO Send message */
  }

  /* TODO EOF in stdin, shutdown the connection */
  
  return 0;
}

void secure_connect(const char* hostname, const char *port) {

  char buf[BUFFER_SIZE];

  /* TODO Establish SSL context and connection */
  /* TODO Print stats about connection */
  const SSL_METHOD* method = TLS_method();
  if (method == NULL)
    report_and_exit("TLS_method failed");
  SSL_CTX* ctx = SSL_CTX_new(method);
  if (ctx == NULL)
      report_and_exit("SSL_CTX_new failed");
  BIO* bio = BIO_new_ssl_connect(ctx);
  if (bio == NULL)
      report_and_exit("BIO_new_ssl_connect failed");

  SSL *ssl = NULL;
  char name[BUFFER_SIZE];
  sprintf(name, "%s:%s", hostname, port);

  BIO_get_ssl(bio, &ssl); /* session */
  SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY); /* mode */
  BIO_set_conn_hostname(bio, name); /* hostname */

  if (BIO_do_connect(bio) <= 0) {
    cleanup(ctx, bio);
    report_and_exit("BIO_do_connect failed");
  }

  SSL_SESSION * session = SSL_get_session(ssl);
  unsigned char master_key[BUFFER_SIZE];
  SSL_SESSION_get_master_key(session, master_key, BUFFER_SIZE);
  fprintf(stderr, "\nMaster Key:\n");

  for(int n=0; master_key[n] != '\0'; n++)
    fprintf(stderr, "%02x", master_key[n]);

  fprintf(stderr, "\n\nSupported cipher suites:\n");
  int count = 0;
  while (SSL_get_cipher_list(ssl, count)) {
    printf("   %s\n", SSL_get_cipher_list(ssl, count));
    count++;
  }
  printf("Using cipher suite: %s\n", SSL_get_cipher(ssl));

   
  X509 *certs;
  certs = SSL_get_peer_certificate(ssl);
  fprintf(stderr, "\n\nCertificate version     :  ");

  if (certs != NULL)
  {
    long version = X509_get_version(certs);
    fprintf(stderr,"%ld\n", version);
    X509_STORE *x509_str = X509_STORE_new();
    X509_STORE_add_cert( x509_str, certs);
    X509_STORE_CTX *x509_ctx = X509_STORE_CTX_new();

    X509_STORE_CTX_init(x509_ctx, x509_str, certs, NULL);
    int ctx_int = X509_verify_cert(x509_ctx);
    fprintf(stderr, "Certificate verification:  ");
    fprintf(stderr,"%s\n", X509_verify_cert_error_string(ctx_int));
    ASN1_TIME* start = X509_getm_notBefore(certs);
    ASN1_TIME* end = X509_getm_notAfter(certs);
    if(start->type == V_ASN1_UTCTIME)
    {
      fprintf(stderr, "Certificate start time  :  ");
      fprintf(stderr,"%s\n", start->data);
    }
    if(end->type == V_ASN1_UTCTIME)
    {
      fprintf(stderr, "Certificate end time    :  ");
      fprintf(stderr,"%s\n", end->data);
    }
    free(start);
    free(end);
    char *line;
    line = X509_NAME_oneline(X509_get_subject_name(certs), 0, 0);
    fprintf(stderr, "Certificate Subject:\n %s\n", line);
    free(line);
    line = X509_NAME_oneline(X509_get_issuer_name(certs), 0, 0);
    fprintf(stderr,"Certificate Issuer:\n %s\n", line);
    free(line);
    EVP_PKEY * pub_key = X509_get_pubkey(certs);
    BIO* pub_bio;
    free(pub_key);
    X509_STORE_CTX_free(x509_ctx);
  }
  else
  {
    fprintf(stderr,"NONE\n");
  }
  


  /* Create thread that will read data from stdin */
  pthread_t thread;
  pthread_create(&thread, NULL, read_user_input, ssl);
  pthread_detach(thread);

  fprintf(stderr, "\nType your message:\n\n");

  /* TODO Receive messages and print them to stdout */
}

int main(int argc, char *argv[]) {
  init_ssl();
  
  const char* hostname;
  const char* port = "443";

  if (argc < 2) {
    fprintf(stderr, "Usage: %s hostname [port]\n", argv[0]);
    return 1;
  }

  hostname = argv[1];
  if (argc > 2)
    port = argv[2];
  
  fprintf(stderr, "Host: %s\nPort: %s\n\n", hostname, port);
  secure_connect(hostname, port);
  
  return 0;
}
