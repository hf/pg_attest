#include "sys/select.h"
#include "sys/socket.h"
#include "sys/un.h"
#include "unistd.h"

#include "postgres.h"
#include "executor/spi.h"
#include "fmgr.h"
#include "utils/builtins.h"
#include "utils/guc.h"

PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(raw_attest);

static const char *ATTESTATION_QUERY =
    ""
    "SELECT json_build_object("
    "  'type', 'request_attestation',"
    "  'timestamp', EXTRACT(EPOCH FROM CURRENT_TIMESTAMP(0)),"
    "  'proofs', json_build_object("
    "    'current_user', current_user,"
    "    'session_user', session_user"
    "  )"
    ");";

static const char *select_attestation_request() {
  int ret = SPI_exec(ATTESTATION_QUERY, 1);
  int proc = SPI_processed;

  if (ret > 0 && SPI_tuptable != NULL) {
    TupleDesc tupdesc = SPI_tuptable->tupdesc;
    SPITupleTable *tuptable = SPI_tuptable;

    for (int i = 0; i < proc; i += 1) {
      HeapTuple tuple = tuptable->vals[i];

      return SPI_getvalue(tuple, tupdesc, 1);
    }
  }

  return NULL;
}

Datum raw_attest(PG_FUNCTION_ARGS) {
  text *retval = NULL;

  int fd, err;
  ssize_t len;
  fd_set rfds;
  struct timeval tv = {0,0};
  char *buf = NULL;
  const size_t buflen = 2 * getpagesize();

  SPI_connect();

  const char *req = select_attestation_request();
  if (req == NULL) {
    retval = cstring_to_text("failed to create attestation request");
    goto done;
  }

  const size_t reqlen = strlen(req);

  fd = socket(AF_UNIX, SOCK_SEQPACKET, O_CLOEXEC);
  if (fd < 0) {
    err = errno;

    retval = cstring_to_text(strerror(err));
    goto done;
  }

  struct sockaddr_un name;
  memset(&name, 0, sizeof(name));

  const char* agent_socket = GetConfigOption("pg_attest.agent_socket", 0, 0);

  name.sun_family = AF_UNIX;
  strncpy(name.sun_path, agent_socket, sizeof(name.sun_path) - 1);

  if (connect(fd, (const struct sockaddr *)&name, sizeof(name)) < 0) {
    err = errno;

    retval = cstring_to_text(strerror(err));
    goto done;
  }

  len = send(fd, req, reqlen, 0);
  if (len < 0) {
    err = errno;

    retval = cstring_to_text(strerror(err));
    goto cleanup;
  }

  FD_ZERO(&rfds);
  FD_SET(fd, &rfds);

  tv.tv_sec = 1;
  tv.tv_usec = 0;
  int ready = select(1, &rfds, NULL, NULL, &tv);

  if (ready == 0) {
    // timeout
    retval = cstring_to_text("agent did not reply to request in time");
    goto cleanup;
  } else if (ready < 0) {
    err = errno;

    retval = cstring_to_text(strerror(err));
    goto cleanup;
  }

  buf = (char *)palloc(buflen);

  len = recv(fd, buf, buflen-1, 0);
  if (len < 0) {
    int err = errno;

    retval = cstring_to_text(strerror(err));
    goto cleanup;
  }

  if (len > 0) {
    buf[len] = 0;
    retval = cstring_to_text(buf);
  } else {
    retval = cstring_to_text("received empty message");
  }

cleanup:
  if (buf != NULL) {
    pfree(buf);
  }

  close(fd);

done:
  SPI_finish();

  PG_RETURN_TEXT_P(retval);
}
