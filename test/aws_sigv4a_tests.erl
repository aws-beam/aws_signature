%% Based on:
%% https://github.com/aws/smithy-go/blob/main/aws-http-auth/sigv4a/sigv4a_test.go
-module(aws_sigv4a_tests).

-include_lib("eunit/include/eunit.hrl").
-include("aws_sigv4_internal.hrl").

creds_session() ->
  #credentials
    { access_key_id = <<"AKID">>
    , secret_access_key = <<"SECRET">>
    , session_token = <<"SESSION">>
    }.

creds_no_session() ->
  #credentials
    { access_key_id = <<"AKID">>
    , secret_access_key = <<"SECRET">>
    , session_token = <<"">>
    }.

verify_signature(PublicKey, Digest, Signature) ->
  crypto:verify(ecdsa, sha256, Digest, Signature, [PublicKey, secp256r1]).

derive_ecdsa_key_pair_from_secret_test() ->
  %% The Go test is unconditionally skipped, so this just checks that
  %% we can generate a private key and that it looks as expected.
  Credentials =
    #credentials
      { access_key_id = <<"AKISORANDOMAASORANDOM">>
      , secret_access_key = <<"q+jcrXGc+0zWN6uzclKVhvMmUsIfRPa4rlRandom">>
      , session_token = <<"TOKEN">>
      },
  {ok, PrivateKey} = aws_sigv4a_credentials:derive_private_key(Credentials),
  ?assertEqual(<<127,211,189,1,12,13,156,41,33,65,194,183,123,251,222,16,66,
                 201,46,104,54,255,247,73,209,38,158,200,144,252,161,189>>,
               PrivateKey).

-record(sign_request_test,
        { input :: #v4a_sign_request_input{}
        , opts :: #v4_signer_options{}
        , preamble :: binary()
        , signed_headers :: binary()
        , string_to_sign :: binary()
        , date :: binary()
        , token :: binary() | false
        , regions_header :: binary()
        }).

new_request(Body, Headers) ->
  #request
    { method = <<"POST">>
    , url = <<"https://service.region.amazonaws.com">>
    , headers = Headers
    , body = Body
    , host = <<"service.region.amazonaws.com">>
    }.

unix_zero_time() ->
  {{1970, 1, 1}, {0, 0, 0}}.

sign_request_minimal_case_nonseekable_test() ->
  test_sign_request(
    #sign_request_test
      { input =
          #v4a_sign_request_input
            { request = new_request(<<"{}">>, [])
            , payload_hash = <<>>
            , credentials = creds_session()
            , service = <<"dynamodb">>
            , regions = [<<"us-east-1">>, <<"us-west-1">>]
            , time = unix_zero_time()
            }
      , opts = #v4_signer_options{}
      , preamble = <<"AWS4-ECDSA-P256-SHA256 Credential=AKID/19700101/dynamodb/aws4_request">>
      , signed_headers = <<"SignedHeaders=host;x-amz-date;x-amz-region-set;x-amz-security-token">>
      , string_to_sign = <<"AWS4-ECDSA-P256-SHA256\n"
                           "19700101T000000Z\n"
                           "19700101/dynamodb/aws4_request\n"
                           "968265b4e87c6b10c8ec6bcfd63e8002814cb3256d74c6c381f0c31268c80b53">>
      , date = <<"19700101T000000Z">>
      , token = <<"SESSION">>
      , regions_header = <<"us-east-1,us-west-1">>
      }).

sign_request_minimal_case_seekable_test() ->
  test_sign_request(
    #sign_request_test
      { input =
          #v4a_sign_request_input
            { request = new_request(<<"{}">>, [])
            , payload_hash = <<>>
            , credentials = creds_session()
            , service = <<"dynamodb">>
            , regions = [<<"us-east-1">>]
            , time = unix_zero_time()
            }
      , opts = #v4_signer_options{}
      , preamble = <<"AWS4-ECDSA-P256-SHA256 Credential=AKID/19700101/dynamodb/aws4_request">>
      , signed_headers = <<"SignedHeaders=host;x-amz-date;x-amz-region-set;x-amz-security-token">>
      , string_to_sign = <<"AWS4-ECDSA-P256-SHA256\n"
                           "19700101T000000Z\n"
                           "19700101/dynamodb/aws4_request\n"
                           "6fbe2f6247e506a47694e695d825477af6c604184f775050ce3b83e04674d9aa">>
      , date = <<"19700101T000000Z">>
      , token = <<"SESSION">>
      , regions_header = <<"us-east-1">>
      }).

sign_request_minimal_case_no_session_test() ->
  test_sign_request(
    #sign_request_test
      { input =
          #v4a_sign_request_input
            { request = new_request(<<"{}">>, [])
            , payload_hash = <<>>
            , credentials = creds_no_session()
            , service = <<"dynamodb">>
            , regions = [<<"us-east-1">>]
            , time = unix_zero_time()
            }
      , opts = #v4_signer_options{}
      , preamble = <<"AWS4-ECDSA-P256-SHA256 Credential=AKID/19700101/dynamodb/aws4_request">>
      , signed_headers = <<"SignedHeaders=host;x-amz-date;x-amz-region-set">>
      , string_to_sign = <<"AWS4-ECDSA-P256-SHA256\n"
                           "19700101T000000Z\n"
                           "19700101/dynamodb/aws4_request\n"
                           "825ea1f5e80bdb91ac8802e832504d1ff1c3b05b7619ffc273a1565a7600ff5a">>
      , date = <<"19700101T000000Z">>
      , token = false
      , regions_header = <<"us-east-1">>
      }).

sign_request_explicit_unsigned_payload_test() ->
  test_sign_request(
    #sign_request_test
      { input =
          #v4a_sign_request_input
            { request = new_request(<<"{}">>, [])
            , payload_hash = ?UNSIGNED_PAYLOAD
            , credentials = creds_session()
            , service = <<"dynamodb">>
            , regions = [<<"us-east-1">>]
            , time = unix_zero_time()
            }
      , opts = #v4_signer_options{}
      , preamble = <<"AWS4-ECDSA-P256-SHA256 Credential=AKID/19700101/dynamodb/aws4_request">>
      , signed_headers = <<"SignedHeaders=host;x-amz-date;x-amz-region-set;x-amz-security-token">>
      , string_to_sign = <<"AWS4-ECDSA-P256-SHA256\n"
                           "19700101T000000Z\n"
                           "19700101/dynamodb/aws4_request\n"
                           "69e5041f5ff858ee8f53a30e5f98cdb4c6bcbfe0f8e61b8aba537d2713bf41a4">>
      , date = <<"19700101T000000Z">>
      , token = <<"SESSION">>
      , regions_header = <<"us-east-1">>
      }).

sign_request_explicit_payload_hash_test() ->
  test_sign_request(
    #sign_request_test
      { input =
          #v4a_sign_request_input
            { request = new_request(<<"{}">>, [])
            , payload_hash = aws_sigv4_utils:sha256(<<"{}">>)
            , credentials = creds_session()
            , service = <<"dynamodb">>
            , regions = [<<"us-east-1">>]
            , time = unix_zero_time()
            }
      , opts = #v4_signer_options{}
      , preamble = <<"AWS4-ECDSA-P256-SHA256 Credential=AKID/19700101/dynamodb/aws4_request">>
      , signed_headers = <<"SignedHeaders=host;x-amz-date;x-amz-region-set;x-amz-security-token">>
      , string_to_sign = <<"AWS4-ECDSA-P256-SHA256\n"
                           "19700101T000000Z\n"
                           "19700101/dynamodb/aws4_request\n"
                           "6fbe2f6247e506a47694e695d825477af6c604184f775050ce3b83e04674d9aa">>
      , date = <<"19700101T000000Z">>
      , token = <<"SESSION">>
      , regions_header = <<"us-east-1">>
      }).

sign_request_sign_all_headers_test() ->
  test_sign_request(
    #sign_request_test
      { input =
          #v4a_sign_request_input
            { request = new_request(<<"{}">>,
                                    [ {<<"Content-Type">>, <<"application/json">>}
                                    , {<<"Foo">>, <<"bar">>}
                                    , {<<"Bar">>, <<"baz">>}
                                    ])
            , payload_hash = aws_sigv4_utils:sha256(<<"{}">>)
            , credentials = creds_session()
            , service = <<"dynamodb">>
            , regions = [<<"us-east-1">>]
            , time = unix_zero_time()
            }
      , opts = #v4_signer_options{is_signed = fun(_) -> true end}
      , preamble = <<"AWS4-ECDSA-P256-SHA256 Credential=AKID/19700101/dynamodb/aws4_request">>
      , signed_headers = <<"SignedHeaders=bar;content-type;foo;host;x-amz-date;x-amz-region-set;x-amz-security-token">>
      , string_to_sign = <<"AWS4-ECDSA-P256-SHA256\n"
                           "19700101T000000Z\n"
                           "19700101/dynamodb/aws4_request\n"
                           "b28cca9faeaa86f4dbfcc3113b05b38f53cd41f41448a41e08e0171cea8ec363">>
      , date = <<"19700101T000000Z">>
      , token = <<"SESSION">>
      , regions_header = <<"us-east-1">>
      }).

sign_request_disable_implicit_payload_hash_test() ->
  test_sign_request(
    #sign_request_test
      { input =
          #v4a_sign_request_input
            { request = new_request(<<"{}">>, [])
            , payload_hash = <<"">>
            , credentials = creds_session()
            , service = <<"dynamodb">>
            , regions = [<<"us-east-1">>]
            , time = unix_zero_time()
            }
      , opts = #v4_signer_options{disable_implicit_payload_hashing = true}
      , preamble = <<"AWS4-ECDSA-P256-SHA256 Credential=AKID/19700101/dynamodb/aws4_request">>
      , signed_headers = <<"SignedHeaders=host;x-amz-date;x-amz-region-set;x-amz-security-token">>
      , string_to_sign = <<"AWS4-ECDSA-P256-SHA256\n"
                           "19700101T000000Z\n"
                           "19700101/dynamodb/aws4_request\n"
                           "69e5041f5ff858ee8f53a30e5f98cdb4c6bcbfe0f8e61b8aba537d2713bf41a4">>
      , date = <<"19700101T000000Z">>
      , token = <<"SESSION">>
      , regions_header = <<"us-east-1">>
      }).

sign_request_disable_s3_settings_test() ->
  test_sign_request(
    #sign_request_test
      { input =
          #v4a_sign_request_input
            { request = new_request(<<"{}">>, [])
            , payload_hash = <<"">>
            , credentials = creds_session()
            , service = <<"s3">>
            , regions = [<<"us-east-1">>]
            , time = unix_zero_time()
            }
      , opts =
          #v4_signer_options
            { disable_double_path_escape = true
            , add_payload_hash_header = true
            }
      , preamble = <<"AWS4-ECDSA-P256-SHA256 Credential=AKID/19700101/s3/aws4_request">>
      , signed_headers = <<"SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-region-set;x-amz-security-token">>
      , string_to_sign = <<"AWS4-ECDSA-P256-SHA256\n"
                           "19700101T000000Z\n"
                           "19700101/s3/aws4_request\n"
                           "3cf4ba7f150421e93dbc22112484147af6e355676d08a75799cfd32424458d7f">>
      , date = <<"19700101T000000Z">>
      , token = <<"SESSION">>
      , regions_header = <<"us-east-1">>
      }).

-spec test_sign_request(#sign_request_test{}) -> ok.
test_sign_request(TT) ->
  Input = TT#sign_request_test.input,
  {ok, Headers} = aws_sigv4a:sign_request(TT#sign_request_test.opts, Input),
  %% The Go test fails to check the token header.
  ?assertEqual(TT#sign_request_test.token, get_header_opt(<<"X-Amz-Security-Token">>, Headers)),
  expect_signature(Headers, TT),
  ?assertEqual(Input#v4a_sign_request_input.request#request.host, get_header(<<"Host">>, Headers)).

-spec expect_signature(aws_sigv4_internal:headers(), #sign_request_test{}) -> ok.
expect_signature(Headers, TT) ->
  {Preamble, SignedHeaders, Signature} = get_signature(Headers),
  ?assertEqual(TT#sign_request_test.preamble, Preamble),
  ?assertEqual(TT#sign_request_test.signed_headers, SignedHeaders),
  Credentials = TT#sign_request_test.input#v4a_sign_request_input.credentials,
  {ok, PrivateKey} = aws_sigv4a_credentials:derive_private_key(Credentials),
  PublicKey = public_key(PrivateKey),
  verify_signature(PublicKey, aws_sigv4_utils:sha256(TT#sign_request_test.string_to_sign), Signature).

public_key(PrivateKey) ->
  {PublicKey, _PrivateKey} = crypto:generate_key(ecdh, secp256r1, PrivateKey),
  PublicKey.

-spec get_signature(aws_sigv4_internal:headers()) -> {binary(), binary(), binary()}.
get_signature(Headers) ->
  Auth = get_header(<<"Authorization">>, Headers),
  [Preamble, SignedHeaders, SigPart] = binary:split(Auth, <<", ">>, [global]),
  [_Key, Hex] = binary:split(SigPart, <<"=">>, [global]),
  Signature = binary:decode_hex(Hex),
  {Preamble, SignedHeaders, Signature}.

-spec get_header(binary(), aws_sigv4_internal:headers()) -> binary().
get_header(Key, Headers) ->
  {_Key, Hdr} = lists:keyfind(Key, 1, Headers),
  Hdr.

-spec get_header_opt(binary(), aws_sigv4_internal:headers()) -> binary() | false.
get_header_opt(Key, Headers) ->
  case lists:keyfind(Key, 1, Headers) of
    false -> false;
    {_Key, Hdr} -> Hdr
  end.

%% TestSignRequest_SignStringError - n/a
