#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "erl_nif.h"
#include "bcrypt.h"
#include "queue.h"

/* Static Erlang Terms */

#define ATOM(Val) (enif_make_atom(env, Val))
#define PAIR(A, B) (enif_make_tuple2(env, A, B))
#define TERM_EQ(lhs, rhs) (enif_compare(lhs, rhs) == 0)
#define ASYNC(R) (PAIR(ATOM_ECRYPT, R))

#define ATOM_OK                  ATOM("ok")
#define ATOM_BADARG              ATOM("badarg")
#define ATOM_EALLOC              ATOM("ealloc")
#define ATOM_ERROR               ATOM("error")

#define ATOM_ECRYPT              ATOM("ecrypt")
#define ATOM_BCRYPT_HASH         ATOM("bcrypt_hash")
#define ATOM_BCRYPT_SALT         ATOM("bcrypt_salt")

#define ERROR_BADARG             PAIR(ATOM_ERROR, ATOM_BADARG)
#define ERROR_EALLOC             PAIR(ATOM_ERROR, ATOM_EALLOC)

/* Support */

static ERL_NIF_TERM
make_reference(ErlNifEnv *env, void *res) {
  ERL_NIF_TERM ref = enif_make_resource(env, res);
  enif_release_resource(res);
  return ref;
}

/* Type Definitions */

typedef struct {
  ErlNifTid tid;
  ErlNifThreadOpts *opts;
  queue *msgs;
} ErlProc;

static ErlNifResourceType *ErlProcType;

typedef struct Message Message;
typedef ERL_NIF_TERM (*ErlProcFn)(ErlProc *, Message *);

struct Message {
  ErlNifEnv *env;
  ErlNifPid from;
  ErlProcFn func;
  ERL_NIF_TERM term;
};

/* Implementation */

static ERL_NIF_TERM
ErlBCrypt_hash_async(ErlProc *proc, Message *msg) {
  ErlNifEnv *env = msg->env;
  int arity;
  const ERL_NIF_TERM *args;
  ErlNifBinary data, salt;
  if (!enif_get_tuple(env, msg->term, &arity, &args) || arity != 2)
    return ASYNC(ERROR_BADARG);
  if (!enif_inspect_iolist_as_binary(env, args[0], &data))
    return ASYNC(ERROR_BADARG);
  if (!enif_inspect_iolist_as_binary(env, args[1], &salt))
    return ASYNC(ERROR_BADARG);

  char hash[BCRYPT_HASHLEN] = {0};
  bcrypt_hash(hash, (char *)data.data, data.size, (char *)salt.data);

  ERL_NIF_TERM term;
  unsigned char *buf = enif_make_new_binary(env, sizeof(hash), &term);
  memcpy(buf, hash, sizeof(hash));
  return ASYNC(term);
}

static ERL_NIF_TERM
ErlBCrypt_salt_async(ErlProc *proc, Message *msg) {
  ErlNifEnv *env = msg->env;

  unsigned int log_rounds;
  if (!enif_get_uint(env, msg->term, &log_rounds))
    return ASYNC(ERROR_BADARG);

  unsigned char csalt[BCRYPT_CSALTLEN] = {0};
  char salt[BCRYPT_SALTLEN] = {0};
  arc4random_buf(csalt, sizeof(csalt));
  bcrypt_salt(salt, csalt, log_rounds);

  ERL_NIF_TERM term;
  unsigned char *buf = enif_make_new_binary(env, sizeof(salt), &term);
  memcpy(buf, salt, sizeof(salt));
  return ASYNC(term);
}

static void
Message_free(Message *msg) {
  if (msg->env)
    enif_free_env(msg->env);
  enif_free(msg);
}

static Message *
Message_new(ErlNifEnv *env, ErlProcFn func, ERL_NIF_TERM term) {
  Message *msg;
  if (!(msg = (Message *)enif_alloc(sizeof(Message))))
    return NULL;

  if (!(msg->env = enif_alloc_env())) {
    Message_free(msg);
    return NULL;
  }

  if (env)
    enif_self(env, &msg->from);

  msg->func = func;
  msg->term = term ? enif_make_copy(msg->env, term) : 0;
  return msg;
}

static void
ErlProc_free(ErlNifEnv *env, void *res) {
  ErlProc *proc = (ErlProc *)res;
  Message *stop = Message_new(NULL, NULL, 0);

  queue_push(proc->msgs, stop);

  enif_thread_join(proc->tid, NULL);
  enif_thread_opts_destroy(proc->opts);

  while (!queue_empty(proc->msgs))
    Message_free(queue_pop(proc->msgs));

  queue_free(proc->msgs);
}

static void *
ErlProc_run(void *arg) {
  ErlProc *proc = (ErlProc *)arg;
  int done = 0;

  while (!done) {
    Message *msg = queue_pop(proc->msgs);
    if (msg->func)
      enif_send(NULL, &msg->from, msg->env, msg->func(proc, msg));
    else
      done = 1;
    Message_free(msg);
  }

  return NULL;
}

static ErlProc *
ErlProc_start(ErlNifEnv *env) {
  ErlProc *proc;
  if (!(proc = enif_alloc_resource(ErlProcType, sizeof(ErlProc))))
    goto error;
  if (!(proc = memset(proc, 0, sizeof(ErlProc))))
    goto error;
  if (!(proc->msgs = queue_new()))
    goto error;
  if (!(proc->opts = enif_thread_opts_create("ecrypt_opts")))
    goto error;
  if (enif_thread_create("ecrypt", &proc->tid, &ErlProc_run, proc, proc->opts))
    goto error;
  return proc;

 error:
  if (proc)
    enif_release_resource(proc);
  return NULL;
}

static ERL_NIF_TERM
ErlProc_init(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
  ErlProc *proc;
  if (!(proc = ErlProc_start(env)))
    return ERROR_EALLOC;
  return make_reference(env, proc);
}

static ERL_NIF_TERM
ErlProc_call(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
  ErlProc *proc;
  if (!enif_get_resource(env, argv[0], ErlProcType, (void **)&proc))
    return ERROR_BADARG;

  if (TERM_EQ(argv[1], ATOM_BCRYPT_HASH))
    queue_push(proc->msgs, Message_new(env, &ErlBCrypt_hash_async, argv[2]));
  else if (TERM_EQ(argv[1], ATOM_BCRYPT_SALT))
    queue_push(proc->msgs, Message_new(env, &ErlBCrypt_salt_async, argv[2]));
  else
    return ERROR_BADARG;

  return argv[0];
}

/* NIF Initialization */

static ErlNifFunc nif_funcs[] =
{
  {"init", 0, ErlProc_init},
  {"call", 3, ErlProc_call}
};

static int
on_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info) {
  ErlNifResourceFlags flags = ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER;
  ErlProcType = enif_open_resource_type(env, NULL, "proc", &ErlProc_free, flags, NULL);
  if (ErlProcType == NULL)
    return -1;
  return 0;
}

ERL_NIF_INIT(ecrypt_nif, nif_funcs, &on_load, NULL, NULL, NULL);
