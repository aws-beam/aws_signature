-ifndef(_AWS_SIGV4_INTERNAL_HRL_).
-define(_AWS_SIGV4_INTERNAL_HRL_, true).

-type headers() :: [{binary(), binary()}].

-record(request,
        { method :: binary()
        , url :: binary()
        , headers :: headers()
        , body :: binary()
        , host :: binary()
        }).

%% https://github.com/aws/smithy-go/blob/main/aws-http-auth/credentials/credentials.go

-record(credentials,
        { access_key_id :: binary()
        , secret_access_key :: binary()
        , session_token :: binary()
        }).

%% https://github.com/aws/smithy-go/blob/main/aws-http-auth/v4/v4.go

-type is_signed() :: fun((binary()) -> boolean()).

-record(v4_signer_options,
        { is_signed :: is_signed() | undefined
        , disable_implicit_payload_hashing = false :: boolean()
        , disable_double_path_escape = false :: boolean()
        , add_payload_hash_header = false :: boolean()
        }).

-define(UNSIGNED_PAYLOAD, <<"UNSIGNED-PAYLOAD">>).

%% https://github.com/aws/smithy-go/blob/main/aws-http-auth/internal/v4/signer.go

-type sign_string() :: fun((binary()) -> {ok, binary()} | {error, any()}).

-record(internal_signer,
        { request :: aws_sigv4_internal:request()
        , payload_hash :: binary() % raw binary, NOT hex-encoded
        , time :: calendar:datetime()
        , credentials :: aws_sigv4_internal:credentials()
        , options :: aws_sigv4_internal:v4_signer_options()
        , algorithm :: binary()
        , credential_scope :: binary()
        , sign_string :: sign_string()
        }).

%% https://github.com/aws/smithy-go/blob/main/aws-http-auth/sigv4a/sigv4a.go

-record(v4a_sign_request_input,
        { request :: aws_sigv4_internal:request()
        , payload_hash :: binary() % raw binary, NOT hex-encoded
        , credentials :: aws_sigv4_internal:credentials()
        , service :: binary()
        , regions :: [binary()]
        , time :: calendar:datetime() | undefined
        }).

-endif. % _AWS_SIGV4_INTERNAL_HRL_
