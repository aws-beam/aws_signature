%% Based on:
%% https://github.com/aws/smithy-go/blob/main/aws-http-auth/internal/v4/signer_test.go
-module(aws_sigv4_internal_tests).

-include_lib("eunit/include/eunit.hrl").
-include("aws_sigv4_internal.hrl").

build_canonical_request_signed_payload_test() ->
  Host = <<"service.region.amazonaws.com">>,
  Body = <<"{}">>,
  Request =
    #request
      { method = <<"POST">>
        %% Note: The Go test has a space between /path and 2, but uri_string:parse/1 rejects that.
      , url = << <<"https://">>/binary, Host/binary, <<"/path1/path%202?a=b">>/binary>>
      , headers =
          [ {<<"Host">>, Host}
          , {<<"X-Amz-Foo">>, <<"\t \tbar ">>}
          ]
      , body = Body
      , host = Host
      },
  Credentials =
    #credentials
      { access_key_id = <<"AKID">>
      , secret_access_key = <<"SK">>
      , session_token = <<"TOKEN">>
      },
  V4SignerOptions =
    #v4_signer_options
      { is_signed = fun aws_sigv4_internal:default_is_signed/1
      },
  Signer =
   #internal_signer
     { request = Request
     , payload_hash = aws_sigv4_utils:sha256(Body)
     , time = {{1970, 1, 1}, {0, 0, 0}}
     , credentials = Credentials
     , options = V4SignerOptions
     , algorithm = <<"ALG">>
     , credential_scope = <<"SCOPE">>
     , sign_string = fun(X) -> {error, X} end
     },
  ExpectedRequest =
    <<"POST\n"
      "/path1/path%25202\n"
      "a=b\n"
      "host:service.region.amazonaws.com\n"
      "x-amz-foo:bar\n"
      "\n"
      "host;x-amz-foo\n"
      "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a">>,
  {ActualRequest, _SignedHeaders} = aws_sigv4_internal:build_canonical_request(Signer),
  ?assertEqual(ExpectedRequest, ActualRequest).

build_canonical_request_no_path_test() ->
  Host = <<"service.region.amazonaws.com">>,
  Body = <<"{}">>,
  Request =
    #request
      { method = <<"POST">>
      , url = << <<"https://">>/binary, Host/binary, <<"?a=b">>/binary>>
      , headers =
          [ {<<"Host">>, Host}
          , {<<"X-Amz-Foo">>, <<"\t \tbar ">>}
          ]
      , body = Body
      , host = Host
      },
  Credentials =
    #credentials
      { access_key_id = <<"AKID">>
      , secret_access_key = <<"SK">>
      , session_token = <<"TOKEN">>
      },
  V4SignerOptions =
    #v4_signer_options
      { is_signed = fun aws_sigv4_internal:default_is_signed/1
      },
  Signer =
   #internal_signer
     { request = Request
     , payload_hash = aws_sigv4_utils:sha256(Body)
     , time = {{1970, 1, 1}, {0, 0, 0}}
     , credentials = Credentials
     , options = V4SignerOptions
     , algorithm = <<"ALG">>
     , credential_scope = <<"SCOPE">>
     , sign_string = fun(X) -> {error, X} end
     },
  ExpectedRequest =
    <<"POST\n"
      "/\n"
      "a=b\n"
      "host:service.region.amazonaws.com\n"
      "x-amz-foo:bar\n"
      "\n"
      "host;x-amz-foo\n"
      "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a">>,
  {ActualRequest, _SignedHeaders} = aws_sigv4_internal:build_canonical_request(Signer),
  ?assertEqual(ExpectedRequest, ActualRequest).

build_canonical_request_double_header_test() ->
  Host = <<"service.region.amazonaws.com">>,
  Body = <<"{}">>,
  Request =
    #request
      { method = <<"POST">>
      , url = << <<"https://">>/binary, Host/binary, <<"/">>/binary>>
      , headers =
          [ {<<"X-Amz-Foo">>, <<"\t \tbar ">>}
          , {<<"Host">>, Host}
          , {<<"dontsignit">>, <<"dontsignit">>} % should be skipped
          , {<<"X-Amz-Foo">>, <<"\t \tbaz ">>}
          ]
      , body = Body
      , host = Host
      },
  Credentials =
    #credentials
      { access_key_id = <<"AKID">>
      , secret_access_key = <<"SK">>
      , session_token = <<"TOKEN">>
      },
  V4SignerOptions =
    #v4_signer_options
      { is_signed = fun aws_sigv4_internal:default_is_signed/1
      },
  Signer =
   #internal_signer
     { request = Request
     , payload_hash = aws_sigv4_utils:sha256(Body)
     , time = {{1970, 1, 1}, {0, 0, 0}}
     , credentials = Credentials
     , options = V4SignerOptions
     , algorithm = <<"ALG">>
     , credential_scope = <<"SCOPE">>
     , sign_string = fun(X) -> {error, X} end
     },
  ExpectedRequest =
    <<"POST\n"
      "/\n"
      "\n"
      "host:service.region.amazonaws.com\n"
      "x-amz-foo:bar,baz\n"
      "\n"
      "host;x-amz-foo\n"
      "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a">>,
  {ActualRequest, _SignedHeaders} = aws_sigv4_internal:build_canonical_request(Signer),
  ?assertEqual(ExpectedRequest, ActualRequest).

build_canonical_request_sort_query_test() ->
  Host = <<"service.region.amazonaws.com">>,
  Body = <<"{}">>,
  Request =
    #request
      { method = <<"POST">>
      , url = << <<"https://">>/binary, Host/binary, <<"/?a=b&%20b=c">>/binary>>
      , headers =
          [ {<<"Host">>, Host}
          ]
      , body = Body
      , host = Host
      },
  Credentials =
    #credentials
      { access_key_id = <<"AKID">>
      , secret_access_key = <<"SK">>
      , session_token = <<"TOKEN">>
      },
  V4SignerOptions =
    #v4_signer_options
      { is_signed = fun aws_sigv4_internal:default_is_signed/1
      },
  Signer =
   #internal_signer
     { request = Request
     , payload_hash = ?UNSIGNED_PAYLOAD
     , time = {{1970, 1, 1}, {0, 0, 0}}
     , credentials = Credentials
     , options = V4SignerOptions
     , algorithm = <<"ALG">>
     , credential_scope = <<"SCOPE">>
     , sign_string = fun(X) -> {error, X} end
     },
  ExpectedRequest =
    <<"POST\n"
      "/\n"
      "%20b=c&a=b\n"
      "host:service.region.amazonaws.com\n"
      "\n"
      "host\n"
      "UNSIGNED-PAYLOAD">>,
  {ActualRequest, _SignedHeaders} = aws_sigv4_internal:build_canonical_request(Signer),
  ?assertEqual(ExpectedRequest, ActualRequest).

build_canonical_request_empty_query_test() ->
  Host = <<"service.region.amazonaws.com">>,
  Body = <<"{}">>,
  Request =
    #request
      { method = <<"POST">>
      , url = << <<"https://">>/binary, Host/binary, <<"/?foo">>/binary>>
      , headers =
          [ {<<"Host">>, Host}
          ]
      , body = Body
      , host = Host
      },
  Credentials =
    #credentials
      { access_key_id = <<"AKID">>
      , secret_access_key = <<"SK">>
      , session_token = <<"TOKEN">>
      },
  V4SignerOptions =
    #v4_signer_options
      { is_signed = fun aws_sigv4_internal:default_is_signed/1
      },
  Signer =
   #internal_signer
     { request = Request
     , payload_hash = ?UNSIGNED_PAYLOAD
     , time = {{1970, 1, 1}, {0, 0, 0}}
     , credentials = Credentials
     , options = V4SignerOptions
     , algorithm = <<"ALG">>
     , credential_scope = <<"SCOPE">>
     , sign_string = fun(X) -> {error, X} end
     },
  ExpectedRequest =
    <<"POST\n"
      "/\n"
      "foo=\n"
      "host:service.region.amazonaws.com\n"
      "\n"
      "host\n"
      "UNSIGNED-PAYLOAD">>,
  {ActualRequest, _SignedHeaders} = aws_sigv4_internal:build_canonical_request(Signer),
  ?assertEqual(ExpectedRequest, ActualRequest).

build_canonical_request_unsigned_payload_test() ->
  Host = <<"service.region.amazonaws.com">>,
  Body = <<"{}">>,
  Request =
    #request
      { method = <<"POST">>
        %% Note: The Go test has a space between /path and 2, but uri_string:parse/1 rejects that.
      , url = << <<"https://">>/binary, Host/binary, <<"/path1/path%202?a=b">>/binary>>
      , headers =
          [ {<<"Host">>, Host}
          , {<<"X-Amz-Foo">>, <<"\t \tbar ">>}
          ]
      , body = Body
      , host = Host
      },
  Credentials =
    #credentials
      { access_key_id = <<"AKID">>
      , secret_access_key = <<"SK">>
      , session_token = <<"TOKEN">>
      },
  V4SignerOptions =
    #v4_signer_options
      { is_signed = fun aws_sigv4_internal:default_is_signed/1
      },
  Signer =
   #internal_signer
     { request = Request
     , payload_hash = ?UNSIGNED_PAYLOAD
     , time = {{1970, 1, 1}, {0, 0, 0}}
     , credentials = Credentials
     , options = V4SignerOptions
     , algorithm = <<"ALG">>
     , credential_scope = <<"SCOPE">>
     , sign_string = fun(X) -> {error, X} end
     },
  ExpectedRequest =
    <<"POST\n"
      "/path1/path%25202\n"
      "a=b\n"
      "host:service.region.amazonaws.com\n"
      "x-amz-foo:bar\n"
      "\n"
      "host;x-amz-foo\n"
      "UNSIGNED-PAYLOAD">>,
  {ActualRequest, _SignedHeaders} = aws_sigv4_internal:build_canonical_request(Signer),
  ?assertEqual(ExpectedRequest, ActualRequest).

build_canonical_request_disable_double_escape_test() ->
  Host = <<"service.region.amazonaws.com">>,
  Body = <<"{}">>,
  Request =
    #request
      { method = <<"POST">>
        %% Note: The Go test has a space between /path and 2, but uri_string:parse/1 rejects that.
      , url = << <<"https://">>/binary, Host/binary, <<"/path1/path%202?a=b">>/binary>>
      , headers =
          [ {<<"Host">>, Host}
          , {<<"X-Amz-Foo">>, <<"\t \tbar ">>}
          ]
      , body = Body
      , host = Host
      },
  Credentials =
    #credentials
      { access_key_id = <<"AKID">>
      , secret_access_key = <<"SK">>
      , session_token = <<"TOKEN">>
      },
  V4SignerOptions =
    #v4_signer_options
      { is_signed = fun aws_sigv4_internal:default_is_signed/1
      , disable_double_path_escape = true
      },
  Signer =
   #internal_signer
     { request = Request
     , payload_hash = ?UNSIGNED_PAYLOAD
     , time = {{1970, 1, 1}, {0, 0, 0}}
     , credentials = Credentials
     , options = V4SignerOptions
     , algorithm = <<"ALG">>
     , credential_scope = <<"SCOPE">>
     , sign_string = fun(X) -> {error, X} end
     },
  ExpectedRequest =
    <<"POST\n"
      "/path1/path%202\n"
      "a=b\n"
      "host:service.region.amazonaws.com\n"
      "x-amz-foo:bar\n"
      "\n"
      "host;x-amz-foo\n"
      "UNSIGNED-PAYLOAD">>,
  {ActualRequest, _SignedHeaders} = aws_sigv4_internal:build_canonical_request(Signer),
  ?assertEqual(ExpectedRequest, ActualRequest).

resolve_payload_hash_already_set_test() ->
  ExpectedHash = <<"already set">>,
  Request =
    #request
      { method = <<"METHOD">>
      , url = <<"URL">>
      , headers = []
      , body = <<"BODY">>
      , host = <<"HOST">>
      },
  Credentials =
    #credentials
      { access_key_id = <<"AKID">>
      , secret_access_key = <<"SK">>
      , session_token = <<"TOKEN">>
      },
  V4SignerOptions =
    #v4_signer_options
      {
      },
  Signer0 =
   #internal_signer
     { request = Request
     , payload_hash = ExpectedHash
     , time = {{1970, 1, 1}, {0, 0, 0}}
     , credentials = Credentials
     , options = V4SignerOptions
     , algorithm = <<"ALG">>
     , credential_scope = <<"SCOPE">>
     , sign_string = fun(X) -> {error, X} end
     },
  Signer = aws_sigv4_internal:resolve_payload_hash(Signer0),
  ActualHash = Signer#internal_signer.payload_hash,
  ?assertEqual(ExpectedHash, ActualHash).

resolve_payload_hash_disabled_test() ->
  Request =
    #request
      { method = <<"METHOD">>
      , url = <<"URL">>
      , headers = []
      , body = <<"BODY">>
      , host = <<"HOST">>
      },
  Credentials =
    #credentials
      { access_key_id = <<"AKID">>
      , secret_access_key = <<"SK">>
      , session_token = <<"TOKEN">>
      },
  V4SignerOptions =
    #v4_signer_options
      { disable_implicit_payload_hashing = true
      },
  Signer0 =
   #internal_signer
     { request = Request
     , payload_hash = <<>> % empty to trigger hash calculation
     , time = {{1970, 1, 1}, {0, 0, 0}}
     , credentials = Credentials
     , options = V4SignerOptions
     , algorithm = <<"ALG">>
     , credential_scope = <<"SCOPE">>
     , sign_string = fun(X) -> {error, X} end
     },
  Signer = aws_sigv4_internal:resolve_payload_hash(Signer0),
  ActualHash = Signer#internal_signer.payload_hash,
  ?assertEqual(?UNSIGNED_PAYLOAD, ActualHash).

%% TestResolvePayloadHash_SeekBlowsUp - not applicable

resolve_payload_hash_ok_test() ->
  Body = <<"foo">>,
  ExpectedHash = aws_sigv4_utils:sha256(Body),
  Request =
    #request
      { method = <<"METHOD">>
      , url = <<"URL">>
      , headers = []
      , body = Body
      , host = <<"HOST">>
      },
  Credentials =
    #credentials
      { access_key_id = <<"AKID">>
      , secret_access_key = <<"SK">>
      , session_token = <<"TOKEN">>
      },
  V4SignerOptions =
    #v4_signer_options
      {
      },
  Signer0 =
   #internal_signer
     { request = Request
     , payload_hash = <<>> % empty to trigger hash calculation
     , time = {{1970, 1, 1}, {0, 0, 0}}
     , credentials = Credentials
     , options = V4SignerOptions
     , algorithm = <<"ALG">>
     , credential_scope = <<"SCOPE">>
     , sign_string = fun(X) -> {error, X} end
     },
  Signer = aws_sigv4_internal:resolve_payload_hash(Signer0),
  ActualHash = Signer#internal_signer.payload_hash,
  ?assertEqual(ExpectedHash, ActualHash).

set_required_headers_all_test() ->
  ExpectedHost = <<"foo.service.com">>,
  Request =
    #request
      { method = <<"METHOD">>
      , url = <<"URL">>
      , headers = []
      , body = <<"BODY">>
      , host = ExpectedHost
      },
  ExpectedToken = <<"session_token">>,
  Credentials =
    #credentials
      { access_key_id = <<"AKID">>
      , secret_access_key = <<"SK">>
      , session_token = ExpectedToken
      },
  V4SignerOptions =
    #v4_signer_options
      { add_payload_hash_header = true
      },
  Signer0 =
   #internal_signer
     { request = Request
     , payload_hash = <<0, 1, 2, 3>>
     , time = {{1970, 1, 1}, {0, 0, 0}}
     , credentials = Credentials
     , options = V4SignerOptions
     , algorithm = <<"ALG">>
     , credential_scope = <<"SCOPE">>
     , sign_string = fun(X) -> {error, X} end
     },
  Signer = aws_sigv4_internal:set_required_headers(Signer0),
  ActualHost = get_header(<<"Host">>, Signer),
  ?assertEqual(ExpectedHost, ActualHost),
  ActualDate = get_header(<<"X-Amz-Date">>, Signer),
  ?assertEqual(<<"19700101T000000Z">>, ActualDate),
  ActualToken = get_header(<<"X-Amz-Security-Token">>, Signer),
  ?assertEqual(ExpectedToken, ActualToken),
  ActualSha = get_header(<<"X-Amz-Content-Sha256">>, Signer),
  ?assertEqual(<<"00010203">>, ActualSha).

set_required_headers_unsigned_payload_test() ->
  ExpectedHost = <<"foo.service.com">>,
  Request =
    #request
      { method = <<"METHOD">>
      , url = <<"URL">>
      , headers = []
      , body = <<"BODY">>
      , host = ExpectedHost
      },
  ExpectedToken = <<"session_token">>,
  Credentials =
    #credentials
      { access_key_id = <<"AKID">>
      , secret_access_key = <<"SK">>
      , session_token = ExpectedToken
      },
  V4SignerOptions =
    #v4_signer_options
      { add_payload_hash_header = true
      },
  Signer0 =
   #internal_signer
     { request = Request
     , payload_hash = <<"UNSIGNED-PAYLOAD">>
     , time = {{1970, 1, 1}, {0, 0, 0}}
     , credentials = Credentials
     , options = V4SignerOptions
     , algorithm = <<"ALG">>
     , credential_scope = <<"SCOPE">>
     , sign_string = fun(X) -> {error, X} end
     },
  Signer = aws_sigv4_internal:set_required_headers(Signer0),
  ActualHost = get_header(<<"Host">>, Signer),
  ?assertEqual(ExpectedHost, ActualHost),
  ActualDate = get_header(<<"X-Amz-Date">>, Signer),
  ?assertEqual(ActualDate, <<"19700101T000000Z">>),
  ActualToken = get_header(<<"X-Amz-Security-Token">>, Signer),
  ?assertEqual(ExpectedToken, ActualToken),
  ActualSha = get_header(<<"X-Amz-Content-Sha256">>, Signer),
  ?assertEqual(<<"UNSIGNED-PAYLOAD">>, ActualSha).

get_header(Key, Signer) ->
  {_Key, Hdr} = lists:keyfind(Key, 1, Signer#internal_signer.request#request.headers),
  Hdr.
