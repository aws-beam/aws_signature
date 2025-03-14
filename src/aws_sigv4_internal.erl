%% Based on:
%% https://github.com/aws/smithy-go/blob/main/aws-http-auth/internal/v4/signer.go
-module(aws_sigv4_internal).

-export([ do/1
        , resolve_time/1
        ]).

-ifdef(TEST).
-export([ build_canonical_request/1
        , default_is_signed/1
        , resolve_payload_hash/1
        , set_required_headers/1
        ]).
-endif.

-include("aws_sigv4_internal.hrl").

-type credentials() :: #credentials{}.
-type headers() :: [{binary(), binary()}].
-type internal_signer() :: #internal_signer{}.
-type request() :: #request{}.
-type sign_string() :: fun((binary()) -> {ok, binary()} | {error, any()}).
-type v4_signer_options() :: #v4_signer_options{}.

-export_type([ credentials/0
             , headers/0
             , internal_signer/0
             , request/0
             , sign_string/0
             , v4_signer_options/0
             ]).

-spec do(internal_signer()) -> {ok, headers()} | {error, any()}.
do(Signer) ->
  Signer1 = init(Signer),
  Signer2 = set_required_headers(Signer1),
  {CanonicalRequest, SignedHeaders} = build_canonical_request(Signer2),
  StringToSign = build_string_to_sign(Signer2, CanonicalRequest),
  case sign_string(Signer2, StringToSign) of
    {ok, Signature} -> {ok, set_authorization_header(Signer2, SignedHeaders, Signature)};
    {error, _Reason} = Error -> Error
  end.

-spec set_authorization_header(internal_signer(), binary(), binary()) -> headers().
set_authorization_header(Signer, SignedHeaders, Signature) ->
  headers_put(<<"Authorization">>,
              build_authorization_header(Signer, SignedHeaders, Signature),
              Signer#internal_signer.request#request.headers).

-spec init(internal_signer()) -> internal_signer().
init(Signer) ->
  resolve_payload_hash(init_is_signed(Signer)).

-spec init_is_signed(internal_signer()) -> internal_signer().
init_is_signed(Signer) ->
  Options = Signer#internal_signer.options,
  case Options#v4_signer_options.is_signed of
    undefined ->
      Options1 = Options#v4_signer_options{is_signed = fun default_is_signed/1},
      Signer#internal_signer{options = Options1};
    IsSigned when is_function(IsSigned, 1) -> Signer
  end.

-spec resolve_payload_hash(internal_signer()) -> internal_signer().
resolve_payload_hash(Signer) ->
  case Signer#internal_signer.payload_hash of
    Binary when byte_size(Binary) > 0 -> Signer;
    _ ->
      PayloadHash =
        case Signer#internal_signer.options#v4_signer_options.disable_implicit_payload_hashing of
          true -> ?UNSIGNED_PAYLOAD;
          false -> aws_sigv4_utils:sha256(Signer#internal_signer.request#request.body)
        end,
      Signer#internal_signer{payload_hash = PayloadHash}
  end.

-spec set_required_headers(internal_signer()) -> internal_signer().
set_required_headers(Signer) ->
  Request0 = Signer#internal_signer.request,
  Headers0 = Request0#request.headers,
  Funs =
    [ fun set_host_header/2
    , fun set_date_header/2
    , fun set_security_token_header/2
    , fun set_content_sha_header/2
    ],
  Headers = lists:foldl(fun(F, Hs) -> F(Signer, Hs) end, Headers0, Funs),
  Request = Request0#request{headers = Headers},
  Signer#internal_signer{request = Request}.

-spec set_host_header(internal_signer(), headers()) -> headers().
set_host_header(#internal_signer{request = #request{host = Host}}, Headers) ->
  headers_put(<<"Host">>, Host, Headers).

-spec set_date_header(internal_signer(), headers()) -> headers().
set_date_header(#internal_signer{time = Time}, Headers) ->
  headers_put(<<"X-Amz-Date">>, aws_sigv4_utils:format_time_long(Time), Headers).

-spec set_security_token_header(internal_signer(), headers()) -> headers().
set_security_token_header(#internal_signer{credentials = Credentials}, Headers) ->
  case Credentials#credentials.session_token of
    SessionToken when byte_size(SessionToken) > 0 ->
      headers_put(<<"X-Amz-Security-Token">>, SessionToken, Headers);
    _ -> Headers
  end.

-spec set_content_sha_header(internal_signer(), headers()) -> headers().
set_content_sha_header(#internal_signer{payload_hash = PayloadHash, options = Options}, Headers) ->
  case PayloadHash of
    _ when byte_size(PayloadHash) > 0, Options#v4_signer_options.add_payload_hash_header =:= true ->
      headers_put(<<"X-Amz-Content-Sha256">>, payload_hash_string(PayloadHash), Headers);
    _ -> Headers
  end.

-spec headers_put(binary(), binary(), headers()) -> headers().
headers_put(Key, Val, Headers) ->
  lists:keystore(Key, 1, Headers, {Key, Val}).

-spec build_canonical_request(internal_signer()) -> {binary(), binary()}.
build_canonical_request(Signer) ->
  CanonMethod = build_canonical_method(Signer),
  CanonPath = build_canonical_path(Signer),
  CanonQuery = build_canonical_query(Signer),
  {CanonHeaders, SignedHeaders} = build_canonical_headers(Signer),
  {iolist_to_binary(
     lists:join("\n",
                [ CanonMethod
                , CanonPath
                , CanonQuery
                , CanonHeaders
                , SignedHeaders
                , payload_hash_string(Signer#internal_signer.payload_hash)
                ])),
   SignedHeaders}.

-spec build_canonical_method(internal_signer()) -> binary().
build_canonical_method(Signer) ->
  string:uppercase(Signer#internal_signer.request#request.method).

-spec build_canonical_path(internal_signer()) -> binary().
build_canonical_path(Signer) ->
  URIMap = uri_string:parse(Signer#internal_signer.request#request.url),
  Path = maps:get(path, URIMap, <<>>),
  %% FIXME: we want an escaped path here, it's unclear if it already is
  EscapedPath =
    case byte_size(Path) =:= 0 of
      true -> <<"/">>;
      false -> Path
    end,
  case Signer#internal_signer.options#v4_signer_options.disable_double_path_escape of
    true -> EscapedPath;
    false -> aws_signature_utils:uri_encode_path(EscapedPath)
  end.

-spec build_canonical_query(internal_signer()) -> binary().
build_canonical_query(Signer) ->
  URIMap = uri_string:parse(Signer#internal_signer.request#request.url),
  QueryString = maps:get(query, URIMap, <<"">>),
  QueryList0 = uri_string:dissect_query(QueryString),
  QueryMap0 =
    lists:foldl(
      fun({Key, Val0}, QMap) ->
        %% treat "key" like "key="
        Val = case Val0 of true -> <<>>; _ -> Val0 end,
        Vals = maps:get(Key, QMap, []),
        maps:put(Key, [Val | Vals], QMap)
      end, maps:new(), QueryList0),
  QueryMap1 =
    maps:map(
      fun(_Key, Vals) ->
        lists:reverse(Vals)
      end, QueryMap0),
  QueryList2 =
    lists:sort(
      fun({K1, _Vs1}, {K2, _Vs2}) ->
        K1 =< K2
      end, maps:to_list(QueryMap1)),
  QueryList3 =
    lists:append(
      lists:map(
        fun({K, Vs}) ->
          lists:map(fun(V) -> {K, V} end, Vs)
        end, QueryList2)),
  case QueryList3 of
    [] -> <<>>;
    _ -> binary:replace(uri_string:compose_query(QueryList3), <<"+">>, <<"%20">>)
  end.

-spec build_canonical_headers(internal_signer()) -> {binary(), binary()}.
build_canonical_headers(Signer) ->
  IsSigned = Signer#internal_signer.options#v4_signer_options.is_signed,
  SignedHeadersMap =
    lists:foldl(
      fun({Header, Value}, Map) ->
        Lowercase = string:lowercase(Header),
        case IsSigned(Lowercase) of
          true ->
            Values = maps:get(Lowercase, Map, []),
            maps:put(Lowercase, [Value | Values], Map);
          false -> Map
        end
      end, maps:new(), Signer#internal_signer.request#request.headers),
  SignedHeadersList = lists:sort(maps:to_list(SignedHeadersMap)),
  SignedHeaders =
    iolist_to_binary(
      lists:map(
        fun({Header, Values}) ->
          [ Header
          , ":"
          , lists:join(",", lists:map(fun string:trim/1, lists:reverse(Values)))
          , "\n"
          ]
        end, SignedHeadersList)),
  CanonHeaders =
    iolist_to_binary(
      lists:join(";", lists:map(fun({Header, _Values}) -> Header end, SignedHeadersList))),
  {SignedHeaders, CanonHeaders}.

-spec build_string_to_sign(internal_signer(), binary()) -> binary().
build_string_to_sign(Signer, CanonicalRequest) ->
  iolist_to_binary(
    lists:join("\n",
               [ Signer#internal_signer.algorithm
               , aws_sigv4_utils:format_time_long(Signer#internal_signer.time)
               , Signer#internal_signer.credential_scope
               , aws_sigv4_utils:sha256(CanonicalRequest)
               ])).

-spec build_authorization_header(internal_signer(), binary(), binary()) -> binary().
build_authorization_header(Signer, SignedHeaders, Signature) ->
  iolist_to_binary(
    [ Signer#internal_signer.algorithm
    , " Credential="
    , Signer#internal_signer.credentials#credentials.access_key_id
    , "/"
   , Signer#internal_signer.credential_scope
    , ", SignedHeaders="
    , SignedHeaders
    , ", Signature="
    , Signature
    ]).

-spec payload_hash_string(binary()) -> binary().
payload_hash_string(Hash) ->
  case Hash of
    ?UNSIGNED_PAYLOAD -> Hash;
    _ -> aws_signature_utils:base16(Hash)
  end.

-spec resolve_time(calendar:datetime() | undefined) -> calendar:datetime().
resolve_time(undefined) -> calendar:universal_time();
resolve_time(Time) -> Time.

-spec default_is_signed(binary()) -> boolean().
default_is_signed(Header) ->
  case Header of
    <<"host">> -> true;
    <<"x-amz-", _/binary>> -> true;
    _ -> false
  end.

-spec sign_string(internal_signer(), binary()) -> {ok, binary()} | {error, any()}.
sign_string(Signer, String) ->
  (Signer#internal_signer.sign_string)(String).
