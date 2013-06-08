-module(bcrypt).

-export([init/0,
         hash/2,
         salt/1,
         salt/2]).

wait(Proc) ->
    receive
        {ecrypt, ok} ->
            Proc;
                {ecrypt, Reply} ->
            Reply
    end.

call(Proc, Method, Args) ->
    case ecrypt_nif:call(Proc, Method, Args) of
        Proc when is_binary(Proc) ->
            wait(Proc);
        Error ->
            Error
    end.

init() ->
    ecrypt_nif:init().

hash(Proc, {Data, Salt}) ->
    call(Proc, bcrypt_hash, {Data, Salt});
hash(Proc, Data) ->
    hash(Proc, {Data, salt(Proc)}).

salt(Proc) ->
    salt(Proc, 12).

salt(Proc, LogR) when is_integer(LogR), LogR >= 4, LogR < 32 ->
    call(Proc, bcrypt_salt, LogR).
