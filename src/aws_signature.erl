%% @doc This module contains functions for signing requests to AWS services.
-module(aws_signature).

-export([sign_v4/9, sign_v4/10]).

-type header() :: {binary(), binary()}.
-type headers() :: [header()].

%% @doc Same as `sign_v4/9' with no options.
sign_v4(AccessKeyID, SecretAccessKey, Region, Service, DateTime, Method, URL, Headers, Body) ->
    sign_v4(AccessKeyID, SecretAccessKey, Region, Service, DateTime, Method, URL, Headers, Body, []).

%% @doc Implements the <a href="https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html">Signature Version 4 (SigV4)</a> algorithm.
%%
%% This function takes AWS client credentials and request details,
%% based on which it computes the signature and returns headers
%% extended with the authorization entries.
%%
%% `DateTime' is a datetime tuple used as the request date.
%% You most likely want to set it to the value of `calendar:universal_time()'
%% when making the request.
%%
%% `URL' must be valid, with all components properly escaped.
%% For example, "https://example.com/path%20to" is valid, whereas
%% "https://example.com/path to" is not.
%%
%% It is essential that the provided request details are final
%% and the returned headers are used to make the request. All
%% custom headers need to be assembled before the signature is
%% calculated.
%%
%% The signature is computed by normalizing request details into
%% a well defined format and combining it with the credentials
%% using a number of cryptographic functions. Upon receiving
%% a request, the server calculates the signature using the same
%% algorithm and compares it with the value received in headers.
%% For more details check out the <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html">AWS documentation</a>.
%%
%% The following options are supported:
%%
%% <dl>
%% <dt>`uri_encode_path'</dt>
%% <dd>
%% When `true', the request URI path is URI-encoded during request
%% canonicalization, <strong>which is required for every service except S3</strong>.
%% Note that the given URL should already be properly encoded, so
%% this results in each segment being URI-encoded twice, as expected
%% by AWS. Defaults to `true'.
%% </dd>
%% </dl>
-spec sign_v4(AccessKeyID, SecretAccessKey, Region, Service, DateTime, Method, URL, Headers, Body, Options) -> FinalHeaders when
      AccessKeyID :: binary(),
      SecretAccessKey :: binary(),
      Region :: binary(),
      Service :: binary(),
      DateTime :: calendar:datetime(),
      Method :: binary(),
      URL :: binary(),
      Headers :: headers(),
      Body :: binary(),
      Options :: [Option],
      Option :: {uri_encode_path, boolean()},
      FinalHeaders :: headers().
sign_v4(AccessKeyID, SecretAccessKey, Region, Service, DateTime, Method, URL, Headers, Body, Options)
    when is_binary(AccessKeyID),
         is_binary(SecretAccessKey),
         is_binary(Region),
         is_binary(Service),
         is_tuple(DateTime),
         is_binary(Method),
         is_binary(URL),
         is_list(Headers),
         is_binary(Body) ->
    URIEncodePath = proplists:get_value(uri_encode_path, Options, true),

    LongDate = format_datetime_long(DateTime),
    ShortDate = format_datetime_short(DateTime),
    FinalHeaders0 = add_date_header(Headers, LongDate),
    FinalHeaders = add_content_hash_header(FinalHeaders0, Body),

    CanonicalRequest = canonical_request(Method, URL, FinalHeaders, Body, URIEncodePath),
    HashedCanonicalRequest = aws_signature_utils:sha256_hexdigest(CanonicalRequest),
    CredentialScope = credential_scope(ShortDate, Region, Service),
    SigningKey = signing_key(SecretAccessKey, ShortDate, Region, Service),
    StringToSign = string_to_sign(LongDate, CredentialScope, HashedCanonicalRequest),
    Signature = aws_signature_utils:hmac_sha256_hexdigest(SigningKey, StringToSign),
    SignedHeaders = signed_headers(FinalHeaders),
    Authorization = authorization(AccessKeyID, CredentialScope, SignedHeaders, Signature),

    add_authorization_header(FinalHeaders, Authorization).

%% Formats the given datetime into YYMMDDTHHMMSSZ binary string.
-spec format_datetime_long(calendar:datetime()) -> binary().
format_datetime_long({{Y, Mo, D}, {H, Mn, S}}) ->
    Format = "~4.10.0B~2.10.0B~2.10.0BT~2.10.0B~2.10.0B~2.10.0BZ",
    IsoString = io_lib:format(Format, [Y, Mo, D, H, Mn, S]),
    list_to_binary(IsoString).

%% Formats the given datetime into YYMMDD binary string.
-spec format_datetime_short(calendar:datetime()) -> binary().
format_datetime_short({{Y, Mo, D}, _}) ->
    Format = "~4.10.0B~2.10.0B~2.10.0B",
    IsoString = io_lib:format(Format, [Y, Mo, D]),
    list_to_binary(IsoString).

-spec add_authorization_header(headers(), binary()) -> headers().
add_authorization_header(Headers, Authorization) ->
    [{<<"Authorization">>, Authorization} | Headers].

add_date_header(Headers, LongDate) ->
    [{<<"X-Amz-Date">>, LongDate} | Headers].

%% Adds a X-Amz-Content-SHA256 header which is the hash of the payload.
%%
%% This header is required for S3 when using the v4 signature. Adding it
%% in requests for all services does not cause any issues.
-spec add_content_hash_header(headers(), binary()) -> headers().
add_content_hash_header(Headers, Body) ->
    HashedBody = aws_signature_utils:sha256_hexdigest(Body),
    [{<<"X-Amz-Content-SHA256">>, HashedBody} | Headers].

%% Generates an AWS4-HMAC-SHA256 authorization signature.
-spec authorization(binary(), binary(), binary(), binary()) -> binary().
authorization(AccessKeyID, CredentialScope, SignedHeaders, Signature) ->
    << "AWS4-HMAC-SHA256 ",
       "Credential=", AccessKeyID/binary,
       "/", CredentialScope/binary,
       ",SignedHeaders=", SignedHeaders/binary,
       ",Signature=", Signature/binary >>.

%% Generates a signing key from a secret access key, a short date in YYMMDD
%% format, a region identifier and a service identifier.
-spec signing_key(binary(), binary(), binary(), binary()) -> binary().
signing_key(SecretAccessKey, ShortDate, Region, Service) ->
    SigningKey = << <<"AWS4">>/binary, SecretAccessKey/binary >>,
    SignedDate = aws_signature_utils:hmac_sha256(SigningKey, ShortDate),
    SignedRegion = aws_signature_utils:hmac_sha256(SignedDate, Region),
    SignedService = aws_signature_utils:hmac_sha256(SignedRegion, Service),
    aws_signature_utils:hmac_sha256(SignedService, <<"aws4_request">>).

%% Generates a credential scope from a short date in YYMMDD format,
%% a region identifier and a service identifier.
-spec credential_scope(binary(), binary(),binary()) -> binary().
credential_scope(ShortDate, Region, Service) ->
    aws_signature_utils:binary_join([ShortDate, Region, Service, <<"aws4_request">>], <<"/">>).

%% Generates the text to sign from a long date in YYMMDDTHHMMSSZ format,
%% a credential scope and a hashed canonical request.
-spec string_to_sign(binary(), binary(), binary()) -> binary().
string_to_sign(LongDate, CredentialScope, HashedCanonicalRequest) ->
    aws_signature_utils:binary_join(
        [<<"AWS4-HMAC-SHA256">>, LongDate, CredentialScope, HashedCanonicalRequest],
        <<"\n">>
    ).

%% Processes and merges request values into a canonical request.
-spec canonical_request(binary(), binary(), headers(), binary(), boolean()) -> binary().
canonical_request(Method, URL, Headers, Body, URIEncodePath) ->
    CanonicalMethod = canonical_method(Method),
    {CanonicalURL, CanonicalQueryString} = split_url(URL, URIEncodePath),
    CanonicalHeaders = canonical_headers(Headers),
    SignedHeaders = signed_headers(Headers),
    PayloadHash = aws_signature_utils:sha256_hexdigest(Body),
    aws_signature_utils:binary_join(
        [CanonicalMethod, CanonicalURL, CanonicalQueryString, CanonicalHeaders, SignedHeaders, PayloadHash],
        <<"\n">>
    ).

%% Normalizes HTTP method name by uppercasing it.
-spec canonical_method(binary()) -> binary().
canonical_method(Method) ->
    list_to_binary(string:to_upper(binary_to_list(Method))).

%% Parses the given URL and returns a canonical URI and a canonical
%% query string.
-spec split_url(binary(), boolean()) -> {binary(), binary()}.
split_url(URL, URIEncodePath) ->
    {Path, Query} = aws_signature_utils:parse_path_and_query(URL),
    {canonical_path(Path, URIEncodePath), canonical_query(Query)}.

-spec canonical_path(binary(), boolean()) -> binary().
canonical_path(<<"">>, _URIEncodePath) -> <<"/">>;
canonical_path(Path, true) -> aws_signature_utils:uri_encode_path(Path);
canonical_path(Path, false) -> Path.

%% Normalizes the given query string.
%%
%% Sorts query params by name first, then by value (if present).
%% Appends "=" to params with missing value.
%%
%% For example, "foo=bar&baz" becomes "baz=&foo=bar".
-spec canonical_query(binary()) -> binary().
canonical_query(<<"">>) -> <<"">>;
canonical_query(Query) ->
    Parts = binary:split(Query, <<"&">>, [global]),
    Entries = [binary:split(Part, <<"=">>) || Part <- Parts],
    SortedEntries = lists:sort(fun([K1 | _], [K2 | _]) -> K1 =< K2 end, Entries),
    NormalizedParts = lists:map(fun query_entry_to_string/1, SortedEntries),
    aws_signature_utils:binary_join(NormalizedParts, <<"&">>).

-spec query_entry_to_string([binary()]) -> binary().
query_entry_to_string([K, V]) ->
    <<K/binary, "=", V/binary>>;
query_entry_to_string([K]) ->
    <<K/binary, "=">>.

%% Converts a list of headers to canonical header format.
%%
%% Leading and trailing whitespace around header names and values is
%% stripped, header names are lowercased, and headers are newline-joined
%% in alphabetical order (with a trailing newline).
-spec canonical_headers(headers()) -> binary().
canonical_headers(Headers) ->
    CanonicalHeaders = lists:map(fun canonical_header/1, Headers),
    SortedCanonicalHeaders = lists:sort(fun({N1, _}, {N2, _}) -> N1 =< N2 end, CanonicalHeaders),
    << <<N/binary, ":", V/binary, "\n" >> || {N, V} <- SortedCanonicalHeaders >>.

-spec canonical_header(header()) -> header().
canonical_header({Name, Value}) ->
    N = list_to_binary(string:strip(string:to_lower(binary_to_list(Name)))),
    V = list_to_binary(string:strip(binary_to_list(Value))),
    {N, V}.

%% Converts a list of headers to canonical signed header format.
%%
%% Leading and trailing whitespace around names is stripped, header names
%% are lowercased, and header names are semicolon-joined in alphabetical order.
-spec signed_headers(headers()) -> binary().
signed_headers(Headers) ->
    aws_signature_utils:binary_join(
        lists:sort(lists:map(fun signed_header/1, Headers)),
        <<";">>
    ).

-spec signed_header(header()) -> binary().
signed_header({Name, _}) ->
    list_to_binary(string:strip(string:to_lower(binary_to_list(Name)))).

%%====================================================================

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

%% sign_v4/9 computes AWS Signature Version 4 and returns an updated list of headers
sign_v4_test() ->
    AccessKeyID = <<"access-key-id">>,
    SecretAccessKey = <<"secret-access-key">>,
    Region = <<"us-east-1">>,
    Service = <<"ec2">>,
    DateTime = {{2015, 5, 14}, {16, 50, 5}},
    Method = <<"GET">>,
    URL = <<"https://ec2.us-east-1.amazonaws.com/?Action=DescribeInstances&Version=2014-10-01">>,
    Headers = [{<<"Host">>, <<"ec2.us-east-1.amazonaws.com">>}, {<<"Header">>, <<"Value">>}],
    Body = <<"">>,

    Actual = sign_v4(AccessKeyID, SecretAccessKey, Region, Service, DateTime, Method, URL, Headers, Body),

    Expected = [
        {<<"Authorization">>, <<"AWS4-HMAC-SHA256 Credential=access-key-id/20150514/us-east-1/ec2/aws4_request,SignedHeaders=header;host;x-amz-content-sha256;x-amz-date,Signature=595529f9989556c9ce375ddec1b3e63f9d551fe063738b45909c28b25a34a6cb">>},
        {<<"X-Amz-Content-SHA256">>, <<"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855">>},
        {<<"X-Amz-Date">>, <<"20150514T165005Z">>},
        {<<"Host">>, <<"ec2.us-east-1.amazonaws.com">>},
        {<<"Header">>, <<"Value">>}],

    ?assertEqual(Actual, Expected).

%% sign_v4/9 https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html#example-signature-GET-object
sign_v4_reference_example_1_test() ->
    AccessKeyID = <<"AKIAIOSFODNN7EXAMPLE">>,
    SecretAccessKey = <<"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY">>,
    Region = <<"us-east-1">>,
    Service = <<"s3">>,
    DateTime = {{2013, 5, 24}, {0, 0, 0}},
    Method = <<"GET">>,
    URL = <<"https://examplebucket.s3.amazonaws.com/test.txt">>,
    Headers = [{<<"Host">>, <<"examplebucket.s3.amazonaws.com">>}, {<<"Range">>, <<"bytes=0-9">>}],
    Body = <<"">>,

    Actual = sign_v4(AccessKeyID, SecretAccessKey, Region, Service, DateTime, Method, URL, Headers, Body, [{uri_encode_path, false}]),

    Expected = [
        {<<"Authorization">>, <<"AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41">>},
        {<<"X-Amz-Content-SHA256">>, <<"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855">>},
        {<<"X-Amz-Date">>, <<"20130524T000000Z">>},
        {<<"Host">>, <<"examplebucket.s3.amazonaws.com">>},
        {<<"Range">>, <<"bytes=0-9">>}],

    ?assertEqual(Actual, Expected).

%% sign_v4/9 https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html#example-signature-PUT-object
sign_v4_reference_example_2_test() ->
    AccessKeyID = <<"AKIAIOSFODNN7EXAMPLE">>,
    SecretAccessKey = <<"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY">>,
    Region = <<"us-east-1">>,
    Service = <<"s3">>,
    DateTime = {{2013, 5, 24}, {0, 0, 0}},
    Method = <<"PUT">>,
    URL = <<"https://examplebucket.s3.amazonaws.com/test%24file.text">>,
    Headers = [
        {<<"Host">>, <<"examplebucket.s3.amazonaws.com">>},
        {<<"Date">>, <<"Fri, 24 May 2013 00:00:00 GMT">>},
        {<<"X-Amz-Storage-Class">>, <<"REDUCED_REDUNDANCY">>}],
    Body = <<"Welcome to Amazon S3.">>,

    Actual = sign_v4(AccessKeyID, SecretAccessKey, Region, Service, DateTime, Method, URL, Headers, Body, [{uri_encode_path, false}]),

    Expected = [
        {<<"Authorization">>, <<"AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class,Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd">>},
        {<<"X-Amz-Content-SHA256">>, <<"44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072">>},
        {<<"X-Amz-Date">>, <<"20130524T000000Z">>},
        {<<"Host">>, <<"examplebucket.s3.amazonaws.com">>},
        {<<"Date">>, <<"Fri, 24 May 2013 00:00:00 GMT">>},
        {<<"X-Amz-Storage-Class">>, <<"REDUCED_REDUNDANCY">>}],

    ?assertEqual(Actual, Expected).

%% sign_v4/9 https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html#example-signature-GET-bucket-lifecycle
sign_v4_reference_example_3_test() ->
    AccessKeyID = <<"AKIAIOSFODNN7EXAMPLE">>,
    SecretAccessKey = <<"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY">>,
    Region = <<"us-east-1">>,
    Service = <<"s3">>,
    DateTime = {{2013, 5, 24}, {0, 0, 0}},
    Method = <<"GET">>,
    URL = <<"https://examplebucket.s3.amazonaws.com?lifecycle">>,
    Headers = [{<<"Host">>, <<"examplebucket.s3.amazonaws.com">>}],
    Body = <<"">>,

    Actual = sign_v4(AccessKeyID, SecretAccessKey, Region, Service, DateTime, Method, URL, Headers, Body, [{uri_encode_path, false}]),

    Expected = [
        {<<"Authorization">>, <<"AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543">>},
        {<<"X-Amz-Content-SHA256">>, <<"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855">>},
        {<<"X-Amz-Date">>, <<"20130524T000000Z">>},
        {<<"Host">>, <<"examplebucket.s3.amazonaws.com">>}],

    ?assertEqual(Actual, Expected).

%% sign_v4/9 https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html#example-signature-list-bucket
sign_v4_reference_example_4_test() ->
    AccessKeyID = <<"AKIAIOSFODNN7EXAMPLE">>,
    SecretAccessKey = <<"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY">>,
    Region = <<"us-east-1">>,
    Service = <<"s3">>,
    DateTime = {{2013, 5, 24}, {0, 0, 0}},
    Method = <<"GET">>,
    URL = <<"https://examplebucket.s3.amazonaws.com?max-keys=2&prefix=J">>,
    Headers = [{<<"Host">>, <<"examplebucket.s3.amazonaws.com">>}],
    Body = <<"">>,

    Actual = sign_v4(AccessKeyID, SecretAccessKey, Region, Service, DateTime, Method, URL, Headers, Body, [{uri_encode_path, false}]),

    Expected = [
        {<<"Authorization">>, <<"AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7">>},
        {<<"X-Amz-Content-SHA256">>, <<"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855">>},
        {<<"X-Amz-Date">>, <<"20130524T000000Z">>},
        {<<"Host">>, <<"examplebucket.s3.amazonaws.com">>}],

    ?assertEqual(Actual, Expected).

%% canonical_headers/1 sorted headers by header name
canonical_headers_test() ->
    Headers = [
        {<<"User-Agent">>, <<"aws-sdk-ruby3/3.113.1 ruby/2.7.2 x86_64-linux aws-sdk-s3/1.93.0">>},
        {<<"X-Amz-Server-Side-Encryption-Customer-Algorithm">>, <<"AES256">>},
        {<<"X-Amz-Server-Side-Encryption-Customer-Key-Md5">>, <<"BaUscNABVnd0nRlQecUFPA==">>},
        {<<"X-Amz-Server-Side-Encryption-Customer-Key">>, <<"TIjv09mJiv+331Evgfq8eONO2y/G4aztRqEeAwx9y2U=">>},
        {<<"Content-Md5">>, <<"VDMfSlWzfS823+nFvkpWzg==">>},
        {<<"Host">>, <<"aws-beam-projects-test.s3.amazonaws.com">>}],

    Actual = canonical_headers(Headers),

    Expected =
        <<"content-md5:VDMfSlWzfS823+nFvkpWzg==\n",
          "host:aws-beam-projects-test.s3.amazonaws.com\n",
          "user-agent:aws-sdk-ruby3/3.113.1 ruby/2.7.2 x86_64-linux aws-sdk-s3/1.93.0\n",
          "x-amz-server-side-encryption-customer-algorithm:AES256\n",
          "x-amz-server-side-encryption-customer-key:TIjv09mJiv+331Evgfq8eONO2y/G4aztRqEeAwx9y2U=\n",
          "x-amz-server-side-encryption-customer-key-md5:BaUscNABVnd0nRlQecUFPA==\n">>,

    ?assertEqual(Expected, Actual).

%% canonical_request/5 returns a connical request binary string
canonical_request_test() ->
    Expected =
        <<"GET", $\n,
          "/pa%2520th", $\n,
          "a=&b=1", $\n,
          "host:example.com", $\n, "x-amz-date:20150325T105958Z", $\n, $\n,
          "host;x-amz-date", $\n,
          "230d8358dc8e8890b4c58deeb62912ee2f20357ae92a5cc861b98e68fe31acb5">>,

    Actual = canonical_request(
        <<"get">>,
        <<"https://example.com/pa%20th?b=1&a=">>,
        [{<<"Host">>, <<"example.com">>}, {<<"X-Amz-Date">>, <<"20150325T105958Z">>}],
        <<"body">>,
        true),

    ?assertEqual(Expected, Actual).

%% canonical_request/4 does not encode the path when disabled
canonical_request_with_encode_uri_path_false_test() ->
    Expected =
        <<"GET", $\n,
          "/pa%20th", $\n,
          "", $\n,
          $\n,
          $\n,
          "230d8358dc8e8890b4c58deeb62912ee2f20357ae92a5cc861b98e68fe31acb5">>,

    Actual = canonical_request(
        <<"get">>,
        <<"https://example.com/pa%20th">>,
        [],
        <<"body">>,
        false),

    ?assertEqual(Expected, Actual).

-endif.
