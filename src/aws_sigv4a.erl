%% Based on:
%% https://github.com/aws/smithy-go/blob/main/aws-http-auth/sigv4a/sigv4a.go
-module(aws_sigv4a).

-export([ sign_request/10
        ]).

%% exported for tests
-export([ sign_request/2
        ]).

-include("aws_sigv4_internal.hrl").

-type v4a_sign_request_input() :: #v4a_sign_request_input{}.

-export_type([ v4a_sign_request_input/0
             ]).

-define(ALGORITHM, <<"AWS4-ECDSA-P256-SHA256">>).

-spec sign_request(binary(), binary(), binary(), [binary()], binary(),
                   binary(), binary(), headers(), binary(), map())
       -> {ok, headers()} | {error, any()}.
sign_request(AccessKeyID, SecretAccessKey, SessionToken, Regions,
             Service, Method, URL, Headers, Body, Options) ->
  Credentials =
    #credentials
      { access_key_id = AccessKeyID
      , secret_access_key = SecretAccessKey
      , session_token = SessionToken
      },
  URIMap = uri_string:parse(URL),
  Host = maps:get(host, URIMap, <<>>),
  Request =
    #request
      { method = Method
      , url = URL
      , headers = Headers
      , body = Body
      , host = Host
      },
  V4ASignerOptions =
    #v4_signer_options
      { add_payload_hash_header = maps:get(add_payload_hash_header, Options, false)
      , disable_implicit_payload_hashing = maps:get(disable_implicit_payload_hashing, Options, false)
      },
  V4ASignRequestInput =
    #v4a_sign_request_input
      { request = Request
      , payload_hash = <<"">>
      , credentials = Credentials
      , service = Service
      , regions = Regions
      , time = undefined
      },
  sign_request(V4ASignerOptions, V4ASignRequestInput).

-spec sign_request(aws_sigv4_internal:v4_signer_options(), v4a_sign_request_input())
               -> {ok, headers()} | {error, any()}.
sign_request(Options, SignRequestInput) ->
  case aws_sigv4a_credentials:derive(SignRequestInput#v4a_sign_request_input.credentials) of
    {ok, PrivateKey} ->
      Regions = SignRequestInput#v4a_sign_request_input.regions,
      Headers =
        [ {<<"X-Amz-Region-Set">>, aws_sigv4_utils:binaries_join(<<",">>, Regions)}
        | SignRequestInput#v4a_sign_request_input.request#request.headers
        ],
      Request = SignRequestInput#v4a_sign_request_input.request#request{headers = Headers},
      Time = aws_sigv4_internal:resolve_time(SignRequestInput#v4a_sign_request_input.time),
      InternalSigner =
        #internal_signer
          { request = Request
          , payload_hash = SignRequestInput#v4a_sign_request_input.payload_hash
          , time = Time
          , credentials = SignRequestInput#v4a_sign_request_input.credentials
          , options = Options
          , algorithm = ?ALGORITHM
          , credential_scope = scope(Time, SignRequestInput#v4a_sign_request_input.service)
          , sign_string = sign_string(PrivateKey)
          },
      aws_sigv4_internal:do(InternalSigner);
    Error -> Error
  end.

%% sigv4a.scope
-spec scope(calendar:datetime(), binary()) -> binary().
scope(Time, Service) ->
  <<(aws_sigv4_utils:format_time_short(Time))/binary, $/, Service/binary, $/, <<"aws4_request">>/binary>>.

%% sigv4a.SignString
-spec sign_string(binary()) -> sign_string().
sign_string(PrivateKey) ->
  fun(StrToSign) ->
    {ok, aws_signature_utils:base16(ecdsa_sign(PrivateKey, aws_sigv4_utils:sha256(StrToSign)))}
  end.

ecdsa_sign(PrivateKey, Digest) ->
  crypto:sign(ecdsa, sha256, Digest, [PrivateKey, secp256r1]).
