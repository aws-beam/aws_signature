%% @doc This module contains functions for signing requests to AWS services.
-module(aws_signature).

-export([sign_v4/9, sign_v4/10, sign_v4_query_params/7, sign_v4_query_params/8]).

-type header() :: {binary(), binary()}.
-type headers() :: [header()].
-type query_param() :: {binary(), binary()}.
-type query_params() :: [query_param()].

%% @doc Same as {@link sign_v4/10} with no options.
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
-spec sign_v4(AccessKeyID, SecretAccessKey, Region, Service, DateTime, Method, URL, Headers, Body, Options) -> FinalHeaders
    when AccessKeyID :: binary(),
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
         is_binary(Body),
         is_list(Options) ->
    URIEncodePath = proplists:get_value(uri_encode_path, Options, true),

    URLMap = aws_signature_utils:parse_url(URL),
    LongDate = format_datetime_long(DateTime),
    ShortDate = format_datetime_short(DateTime),
    FinalHeaders0 = add_date_header(Headers, LongDate),
    FinalHeaders = add_content_hash_header(FinalHeaders0, Body),

    BodyDigest = aws_signature_utils:sha256_hexdigest(Body),
    CanonicalRequest = canonical_request(Method, URLMap, FinalHeaders, BodyDigest, URIEncodePath),
    HashedCanonicalRequest = aws_signature_utils:sha256_hexdigest(CanonicalRequest),
    CredentialScope = credential_scope(ShortDate, Region, Service),
    SigningKey = signing_key(SecretAccessKey, ShortDate, Region, Service),
    StringToSign = string_to_sign(LongDate, CredentialScope, HashedCanonicalRequest),
    Signature = aws_signature_utils:hmac_sha256_hexdigest(SigningKey, StringToSign),
    SignedHeaders = signed_headers(FinalHeaders),
    Authorization = authorization(AccessKeyID, CredentialScope, SignedHeaders, Signature),

    add_authorization_header(FinalHeaders, Authorization).

%% @doc Same as {@link sign_v4_query_params/7} with no options.
sign_v4_query_params(AccessKeyID, SecretAccessKey, Region, Service, DateTime, Method, URL) ->
    sign_v4_query_params(AccessKeyID, SecretAccessKey, Region, Service, DateTime, Method, URL, []).

%% @doc Implements the <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html">Signature Version 4 (SigV4)</a> algorithm for query parameters.
%%
%% This function takes AWS client credentials and request details,
%% based on which it computes the signature and returns the URL
%% extended with the signature entries. Note that anchors are ignored
%% in the resulting URL.
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
%% and the returned query params are used to make the request with
%% the provided URL.
%%
%% The signature is computed by normalizing request details into
%% a well defined format and combining it with the credentials
%% using a number of cryptographic functions. Upon receiving
%% a request, the server calculates the signature using the same
%% algorithm and compares it with the value received in headers.
%% For more details check out the <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html">AWS documentation</a>.
%%
%% The following options are supported:
%%
%% <dl>
%% <dt>`ttl'</dt>
%% <dd>
%% Time-to-live value that tells how long this URL is valid in seconds.
%% Defaults to `86400', which means one day.
%% </dd>
%% <dt>`uri_encode_path'</dt>
%% <dd>
%% When `true', the request URI path is URI-encoded during request
%% canonicalization, <strong>which is required for every service except S3</strong>.
%% Note that the given URL should already be properly encoded, so
%% this results in each segment being URI-encoded twice, as expected
%% by AWS. Defaults to `true'.
%% </dd>
%% <dt>`session_token'</dt>
%% <dd>
%% Optional credential parameter if using credentials sourced from the STS service.
%% </dd>
%% <dt>`body'</dt>
%% <dd>
%% Request body to compute SHA256 digest for. Defaults to an empty binary. Note that
%% `body_digest' always takes precedence when set.
%% </dd>
%% <dt>`body_digest'</dt>
%% <dd>
%% Optional SHA256 digest of the request body. This option can be used to provide
%% a fixed digest value, such as "UNSIGNED-PAYLOAD", when sending requests without
%% signing the body, <strong>which is expected for S3</strong>.
%% </dd>
%% </dl>
-spec sign_v4_query_params(AccessKeyID, SecretAccessKey, Region, Service, DateTime, Method, URL, Options) -> FinalURL
    when AccessKeyID :: binary(),
         SecretAccessKey :: binary(),
         Region :: binary(),
         Service :: binary(),
         DateTime :: calendar:datetime(),
         Method :: binary(),
         URL :: binary(),
         Options :: [Option],
         Option ::
             {uri_encode_path, boolean()}
             | {session_token, binary()}
             | {ttl, non_neg_integer()}
             | {body, binary()}
             | {body_digest, binary()},
         FinalURL :: binary().
sign_v4_query_params(AccessKeyID, SecretAccessKey, Region, Service, DateTime, Method, URL, Options)
    when is_binary(AccessKeyID),
         is_binary(SecretAccessKey),
         is_binary(Region),
         is_binary(Service),
         is_tuple(DateTime),
         is_binary(Method),
         is_binary(URL),
         is_list(Options) ->
    URIEncodePath = proplists:get_value(uri_encode_path, Options, true),
    TimeToLive = proplists:get_value(ttl, Options, 86400),
    SessionToken = proplists:get_value(session_token, Options, undefined),
    BodyDigest =
        case proplists:get_value(body_digest, Options, undefined) of
            undefined ->
                Body = proplists:get_value(body, Options, <<"">>),
                aws_signature_utils:sha256_hexdigest(Body);
            Digest ->
                Digest
        end,
    BaseParams =
        [{<<"X-Amz-Algorithm">>, <<"AWS4-HMAC-SHA256">>},
         {<<"X-Amz-SignedHeaders">>, <<"host">>}],

    URLMap = aws_signature_utils:parse_url(URL),
    LongDate = format_datetime_long(DateTime),
    ShortDate = format_datetime_short(DateTime),
    CredentialScope = credential_scope(ShortDate, Region, Service),
    FinalQueryParams0 = add_ttl_query_param(BaseParams, TimeToLive),
    FinalQueryParams1 =
        add_credential_query_param(FinalQueryParams0, CredentialScope, AccessKeyID),
    FinalQueryParams2 = maybe_add_session_token_query_param(FinalQueryParams1, SessionToken),

    FinalQueryParams = add_date_header(FinalQueryParams2, LongDate),
    HostHeader = host_header_from_url(URLMap),

    CanonicalRequest =
        canonical_request(Method, URLMap, [HostHeader], BodyDigest, URIEncodePath, FinalQueryParams),

    HashedCanonicalRequest = aws_signature_utils:sha256_hexdigest(CanonicalRequest),
    SigningKey = signing_key(SecretAccessKey, ShortDate, Region, Service),
    StringToSign = string_to_sign(LongDate, CredentialScope, HashedCanonicalRequest),
    Signature = aws_signature_utils:hmac_sha256_hexdigest(SigningKey, StringToSign),

    build_final_url_with_signature(URL, URLMap, FinalQueryParams, Signature).

%% Formats the given datetime into YYMMDDTHHMMSSZ binary string.
-spec format_datetime_long(calendar:datetime()) -> binary().
format_datetime_long({{Y, Mo, D}, {H, Mn, S}}) ->
    Date = format_date(Y, Mo, D),
    Timestamp = format_timestamp(Date, H, Mn, S),
    Timestamp.

format_date(Y, M0, D0) ->
    M = maybe_add_padding(M0),
    D = maybe_add_padding(D0),
    <<(integer_to_binary(Y))/binary, M/binary, D/binary>>.

format_timestamp(Date, H0, Min0, S0) ->
    H = maybe_add_padding(H0),
    Min = maybe_add_padding(Min0),
    S = maybe_add_padding(S0),
    <<Date/binary, "T", H/binary, Min/binary, S/binary, "Z">>.

maybe_add_padding(X) when X < 10 ->
    <<"0", (integer_to_binary(X))/binary>>;
maybe_add_padding(X) ->
    integer_to_binary(X).

%% Formats the given datetime into YYMMDD binary string.
-spec format_datetime_short(calendar:datetime()) -> binary().
format_datetime_short({{Y, Mo, D}, _}) ->
    format_date(Y, Mo, D).

-spec add_authorization_header(headers(), binary()) -> headers().
add_authorization_header(Headers, Authorization) ->
    [{<<"Authorization">>, Authorization} | Headers].

add_date_header(Headers, LongDate) ->
    [{<<"X-Amz-Date">>, LongDate} | Headers].

add_ttl_query_param(QueryParams, TimeToLive) ->
    [{<<"X-Amz-Expires">>, integer_to_binary(TimeToLive)} | QueryParams].

add_credential_query_param(QueryParams, Scope, AccessKey) ->
    EncodedScope = binary:split(Scope, <<"/">>, [global]),
    [{<<"X-Amz-Credential">>,
      aws_signature_utils:binary_join([AccessKey | EncodedScope], <<"%2F">>)}
     | QueryParams].

host_header_from_url(URLMap) ->
    #{host := Host} = URLMap,
    {<<"Host">>, Host}.

maybe_add_session_token_query_param(QueryParams, undefined) ->
    QueryParams;
maybe_add_session_token_query_param(QueryParams, SessionToken) ->
    [{<<"X-Amz-Security-Token">>, SessionToken} | QueryParams].

sort_query_params_with_signature(QueryParams, Signature) ->
    FinalQueryParams = [{<<"X-Amz-Signature">>, Signature} | QueryParams],

    lists:sort(fun({K1, _}, {K2, _}) -> K1 =< K2 end, FinalQueryParams).

-spec build_final_url_with_signature(binary(), map(), query_params(), binary()) -> binary().
build_final_url_with_signature(OriginalURL, URLMap, QueryParams, Signature) ->
    #{query := Query} = URLMap,

    FinalQueryParams0 = query_entries(Query) ++ QueryParams,
    FinalQueryParams = sort_query_params_with_signature(FinalQueryParams0, Signature),

    aws_signature_utils:rebuilds_url_with_query_params(OriginalURL, FinalQueryParams).

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
-spec credential_scope(binary(), binary(), binary()) -> binary().
credential_scope(ShortDate, Region, Service) ->
    aws_signature_utils:binary_join([ShortDate, Region, Service, <<"aws4_request">>],
                                    <<"/">>).

%% Generates the text to sign from a long date in YYMMDDTHHMMSSZ format,
%% a credential scope and a hashed canonical request.
-spec string_to_sign(binary(), binary(), binary()) -> binary().
string_to_sign(LongDate, CredentialScope, HashedCanonicalRequest) ->
    aws_signature_utils:binary_join([<<"AWS4-HMAC-SHA256">>,
                                     LongDate,
                                     CredentialScope,
                                     HashedCanonicalRequest],
                                    <<"\n">>).

%% Processes and merges request values into a canonical request.
-spec canonical_request(binary(), map(), headers(), binary(), boolean()) -> binary().
canonical_request(Method, URL, Headers, Body, URIEncodePath) ->
    canonical_request(Method, URL, Headers, Body, URIEncodePath, []).

-spec canonical_request(binary(),
                        map(),
                        headers(),
                        binary(),
                        boolean(),
                        query_params()) ->
                           binary().
canonical_request(Method, URLMap, Headers, BodyDigest, URIEncodePath, AdditionalQueryParams) ->
    CanonicalMethod = canonical_method(Method),
    #{path := Path, query := Query} = URLMap,
    CanonicalURL = canonical_path(Path, URIEncodePath),
    QueryEntries = query_entries(Query),
    CanonicalQueryString = canonical_query(QueryEntries ++ AdditionalQueryParams),
    CanonicalHeaders = canonical_headers(Headers),
    SignedHeaders = signed_headers(Headers),
    aws_signature_utils:binary_join([CanonicalMethod,
                                     CanonicalURL,
                                     CanonicalQueryString,
                                     CanonicalHeaders,
                                     SignedHeaders,
                                     BodyDigest],
                                    <<"\n">>).

%% Normalizes HTTP method name by uppercasing it.
-spec canonical_method(binary()) -> binary().
canonical_method(Method) ->
    list_to_binary(string:to_upper(binary_to_list(Method))).

-spec canonical_path(binary(), boolean()) -> binary().
canonical_path(<<"">>, _URIEncodePath) ->
    <<"/">>;
canonical_path(Path, true) ->
    aws_signature_utils:uri_encode_path(Path);
canonical_path(Path, false) ->
    Path.

%% Normalizes the given query string.
%%
%% Sorts query params by name first, then by value (if present).
%% Appends "=" to params with missing value.
%%
%% For example, "foo=bar&baz" becomes "baz=&foo=bar".
-spec canonical_query(query_params()) -> binary().
canonical_query([]) ->
    <<"">>;
canonical_query(QueryParams) when is_list(QueryParams) ->
    SortedParts = lists:sort(fun({K1, _}, {K2, _}) -> K1 =< K2 end, QueryParams),
    NormalizedParts = lists:map(fun query_entry_to_string/1, SortedParts),
    aws_signature_utils:binary_join(NormalizedParts, <<"&">>).

-spec query_entries(binary()) -> [{binary(), binary()}].
query_entries(<<"">>) -> [];
query_entries(Query) ->
    Parts = binary:split(Query, <<"&">>, [global]),
    SplittedParts = [binary:split(Part, <<"=">>) || Part <- Parts],

    lists:map(fun query_entry_to_tuple/1, SplittedParts).

query_entry_to_tuple([Key]) ->
    {Key, <<"">>};
query_entry_to_tuple([Key, Value]) ->
    {Key, Value}.

-spec query_entry_to_string({binary(), binary()}) -> binary().
query_entry_to_string({K, V}) ->
    <<K/binary, "=", V/binary>>.

%% Converts a list of headers to canonical header format.
%%
%% Leading and trailing whitespace around header names and values is
%% stripped, header names are lowercased, and headers are newline-joined
%% in alphabetical order (with a trailing newline).
-spec canonical_headers(headers()) -> binary().
canonical_headers(Headers) ->
    CanonicalHeaders = lists:map(fun canonical_header/1, Headers),
    SortedCanonicalHeaders =
        lists:sort(fun({N1, _}, {N2, _}) -> N1 =< N2 end, CanonicalHeaders),
    << <<N/binary, ":", V/binary, "\n">> || {N, V} <- SortedCanonicalHeaders >>.

-spec canonical_header(header()) -> header().
canonical_header({Name, Value}) ->
    N = list_to_binary(string:strip(
                           string:to_lower(binary_to_list(Name)))),
    V = list_to_binary(string:strip(binary_to_list(Value))),
    {N, V}.

%% Converts a list of headers to canonical signed header format.
%%
%% Leading and trailing whitespace around names is stripped, header names
%% are lowercased, and header names are semicolon-joined in alphabetical order.
-spec signed_headers(headers()) -> binary().
signed_headers(Headers) ->
    aws_signature_utils:binary_join(
        lists:sort(
            lists:map(fun signed_header/1, Headers)),
        <<";">>).

-spec signed_header(header()) -> binary().
signed_header({Name, _}) ->
    list_to_binary(string:strip(
                       string:to_lower(binary_to_list(Name)))).

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
          "content-sha256">>,

    Actual = canonical_request(
        <<"get">>,
        #{path => <<"/pa%20th">>, query => <<"b=1&a=">>},
        [{<<"Host">>, <<"example.com">>}, {<<"X-Amz-Date">>, <<"20150325T105958Z">>}],
        <<"content-sha256">>,
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
          "content-sha256">>,

    Actual =
        canonical_request(<<"get">>, #{path => <<"/pa%20th">>, query => <<"">>}, [], <<"content-sha256">>, false),

    ?assertEqual(Expected, Actual).

%% canonical_request/5 returns a canonical request binary string with extra query params
canonical_request_with_extra_query_params_test() ->
    Expected =
        <<"GET",
          $\n,
          "/pa%2520th",
          $\n,
          "a=&b=1&c=2&d=3",
          $\n,
          "host:example.com",
          $\n,
          "x-amz-date:20150325T105958Z",
          $\n,
          $\n,
          "host;x-amz-date",
          $\n,
          "content-sha256">>,

    Actual =
        canonical_request(<<"get">>,
                          #{path => <<"/pa%20th">>, query => <<"b=1&a=">>},
                          [{<<"Host">>, <<"example.com">>},
                           {<<"X-Amz-Date">>, <<"20150325T105958Z">>}],
                          <<"content-sha256">>,
                          true,
                          [{<<"c">>, <<"2">>}, {<<"d">>, <<"3">>}]),

    ?assertEqual(Expected, Actual).

%% canonical_request/5 returns a canonical request binary string with only additional query params
canonical_request_with_only_additional_query_params_test() ->
    Expected =
        <<"GET",
          $\n,
          "/pa%2520th",
          $\n,
          "c=2&d=3",
          $\n,
          "host:example.com",
          $\n,
          "x-amz-date:20150325T105958Z",
          $\n,
          $\n,
          "host;x-amz-date",
          $\n,
          "content-sha256">>,

    Actual =
        canonical_request(<<"get">>,
                          #{path => <<"/pa%20th">>, query => <<"">>},
                          [{<<"Host">>, <<"example.com">>},
                           {<<"X-Amz-Date">>, <<"20150325T105958Z">>}],
                          <<"content-sha256">>,
                          true,
                          [{<<"c">>, <<"2">>}, {<<"d">>, <<"3">>}]),

    ?assertEqual(Expected, Actual).

%% sign_v4_query_params/7: Example 1 from https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
sign_v4_query_params_reference_example_1_test() ->
    AccessKeyID = <<"AKIAIOSFODNN7EXAMPLE">>,
    SecretAccessKey = <<"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY">>,
    Region = <<"us-east-1">>,
    Service = <<"s3">>,
    DateTime = {{2013, 5, 24}, {0, 0, 0}},
    Method = <<"GET">>,
    URL = <<"https://examplebucket.s3.amazonaws.com/test.txt">>,

    Expected =
        <<"https://examplebucket.s3.amazonaws.com/test.txt?",
        "X-Amz-Algorithm=AWS4-HMAC-SHA256&",
        "X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&",
        "X-Amz-Date=20130524T000000Z&",
        "X-Amz-Expires=86400&",
        "X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404&",
        "X-Amz-SignedHeaders=host">>,

    Actual =
        sign_v4_query_params(AccessKeyID,
                             SecretAccessKey,
                             Region,
                             Service,
                             DateTime,
                             Method,
                             URL,
                             [{body_digest, <<"UNSIGNED-PAYLOAD">>}]),

    ?assertEqual(Expected, Actual).

%% sign_v4_query_params/7: Example 2 from https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
sign_v4_query_params_reference_example_2_with_session_token_test() ->
    AccessKeyID = <<"AKIAIOSFODNN7EXAMPLE">>,
    SecretAccessKey = <<"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY">>,
    Region = <<"us-east-1">>,
    Service = <<"s3">>,
    DateTime = {{2013, 5, 24}, {0, 0, 0}},
    Method = <<"GET">>,
    URL = <<"https://examplebucket.s3.amazonaws.com/test.txt">>,
    SessionToken = <<"my-session-token">>,

    Expected =
        <<"https://examplebucket.s3.amazonaws.com/test.txt?",
          "X-Amz-Algorithm=AWS4-HMAC-SHA256&",
          "X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&",
          "X-Amz-Date=20130524T000000Z&",
          "X-Amz-Expires=86400&",
          "X-Amz-Security-Token=my-session-token&",
          "X-Amz-Signature=127498ec2e996f60915eba27520e69b1554fe016da1d36a3dde70f2408551d67&",
          "X-Amz-SignedHeaders=host">>,

    Actual =
        sign_v4_query_params(AccessKeyID,
                             SecretAccessKey,
                             Region,
                             Service,
                             DateTime,
                             Method,
                             URL,
                             [{body_digest, <<"UNSIGNED-PAYLOAD">>}, {session_token, SessionToken}]),

    ?assertEqual(Expected, Actual).

sign_v4_query_params_merge_existing_query_params_with_ttl_test() ->
    AccessKeyID = <<"AKIAIOSFODNN7EXAMPLE">>,
    SecretAccessKey = <<"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY">>,
    Region = <<"us-east-1">>,
    Service = <<"s3">>,
    DateTime = {{2013, 5, 24}, {0, 0, 0}},
    Method = <<"GET">>,
    URL = <<"https://examplebucket.s3.amazonaws.com/test.txt?A-param=value&X-Another=param">>,

    Expected =
        <<"https://examplebucket.s3.amazonaws.com/test.txt?",
        "A-param=value&",
        "X-Amz-Algorithm=AWS4-HMAC-SHA256&",
        "X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&",
        "X-Amz-Date=20130524T000000Z&",
        "X-Amz-Expires=3600&",
        "X-Amz-Signature=ec8b95e4cf1cc811afc9e29eb7c3959f8832b1ddd36800a082d1c8e6d51f6b8a&",
        "X-Amz-SignedHeaders=host&",
        "X-Another=param">>,

    Actual =
        sign_v4_query_params(AccessKeyID,
                             SecretAccessKey,
                             Region,
                             Service,
                             DateTime,
                             Method,
                             URL,
                             [{ttl, 3600}]),

    ?assertEqual(Expected, Actual).

sign_v4_query_params_with_put_method_test() ->
    AccessKeyID = <<"AKIAIOSFODNN7EXAMPLE">>,
    SecretAccessKey = <<"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY">>,
    Region = <<"us-east-1">>,
    Service = <<"s3">>,
    DateTime = {{2013, 5, 24}, {0, 0, 0}},
    Method = <<"PUT">>,
    URL = <<"https://examplebucket.s3.amazonaws.com/test.txt">>,

    Expected =
        <<"https://examplebucket.s3.amazonaws.com/test.txt?",
        "X-Amz-Algorithm=AWS4-HMAC-SHA256&",
        "X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&",
        "X-Amz-Date=20130524T000000Z&",
        "X-Amz-Expires=86400&",
        "X-Amz-Signature=2f382d203f44c23831e0b740f8bc389dc4367991d3001843c8a4fccefe56a0ad&",
        "X-Amz-SignedHeaders=host">>,

    Actual =
        sign_v4_query_params(AccessKeyID, SecretAccessKey, Region, Service, DateTime, Method, URL, []),

    ?assertEqual(Expected, Actual).

sign_v4_query_params_with_no_body_test() ->
    AccessKeyID = <<"AKIAIOSFODNN7EXAMPLE">>,
    SecretAccessKey = <<"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY">>,
    Region = <<"us-east-1">>,
    Service = <<"s3">>,
    DateTime = {{2013, 5, 24}, {0, 0, 0}},
    Method = <<"GET">>,
    URL = <<"https://examplebucket.s3.amazonaws.com/test.txt">>,

    Expected =
        <<"https://examplebucket.s3.amazonaws.com/test.txt?",
        "X-Amz-Algorithm=AWS4-HMAC-SHA256&",
        "X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&",
        "X-Amz-Date=20130524T000000Z&",
        "X-Amz-Expires=86400&",
        "X-Amz-Signature=2f96f106e896a51445dbd699bd79337027afef2fd1d841506882218daeaf9b3c&",
        "X-Amz-SignedHeaders=host">>,

    Actual =
        sign_v4_query_params(AccessKeyID, SecretAccessKey, Region, Service, DateTime, Method, URL, []),

    ?assertEqual(Expected, Actual).

sign_v4_query_params_with_body_test() ->
    AccessKeyID = <<"AKIAIOSFODNN7EXAMPLE">>,
    SecretAccessKey = <<"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY">>,
    Region = <<"us-east-1">>,
    Service = <<"s3">>,
    DateTime = {{2013, 5, 24}, {0, 0, 0}},
    Method = <<"GET">>,
    URL = <<"https://examplebucket.s3.amazonaws.com/test.txt">>,

    Expected =
        <<"https://examplebucket.s3.amazonaws.com/test.txt?",
        "X-Amz-Algorithm=AWS4-HMAC-SHA256&",
        "X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&",
        "X-Amz-Date=20130524T000000Z&",
        "X-Amz-Expires=86400&",
        "X-Amz-Signature=2f803843262d253ddc309d3bdd705c054cf39f863ce347a35c9b66f8f651a62d&",
        "X-Amz-SignedHeaders=host">>,

    Actual =
        sign_v4_query_params(AccessKeyID,
                             SecretAccessKey,
                             Region,
                             Service,
                             DateTime,
                             Method,
                             URL,
                             [{body, <<"body">>}]),

    ?assertEqual(Expected, Actual).

sign_v4_query_params_with_body_digest_test() ->
    AccessKeyID = <<"AKIAIOSFODNN7EXAMPLE">>,
    SecretAccessKey = <<"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY">>,
    Region = <<"us-east-1">>,
    Service = <<"s3">>,
    DateTime = {{2013, 5, 24}, {0, 0, 0}},
    Method = <<"GET">>,
    URL = <<"https://examplebucket.s3.amazonaws.com/test.txt">>,

    Expected =
        <<"https://examplebucket.s3.amazonaws.com/test.txt?",
        "X-Amz-Algorithm=AWS4-HMAC-SHA256&",
        "X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&",
        "X-Amz-Date=20130524T000000Z&",
        "X-Amz-Expires=86400&",
        "X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404&",
        "X-Amz-SignedHeaders=host">>,

    Actual =
        sign_v4_query_params(AccessKeyID,
                             SecretAccessKey,
                             Region,
                             Service,
                             DateTime,
                             Method,
                             URL,
                             [{body_digest, <<"UNSIGNED-PAYLOAD">>}]),

    ?assertEqual(Expected, Actual).

sign_v4_query_params_with_authority_port_test() ->
    AccessKeyID = <<"AKIAIOSFODNN7EXAMPLE">>,
    SecretAccessKey = <<"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY">>,
    Region = <<"us-east-1">>,
    Service = <<"s3">>,
    DateTime = {{2013, 5, 24}, {0, 0, 0}},
    Method = <<"GET">>,
    URL = <<"http://bucket.localhost:9000/test.txt">>,

    Expected =
        <<"http://bucket.localhost:9000/test.txt?",
        "X-Amz-Algorithm=AWS4-HMAC-SHA256&",
        "X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&",
        "X-Amz-Date=20130524T000000Z&",
        "X-Amz-Expires=86400&",
        "X-Amz-Signature=3dd62e9f64b1c393bfc3d2902e5d5474b629113acd965dbd52ea3d874c83921b&",
        "X-Amz-SignedHeaders=host">>,

    Actual =
        sign_v4_query_params(AccessKeyID,
                             SecretAccessKey,
                             Region,
                             Service,
                             DateTime,
                             Method,
                             URL,
                             [{body_digest, <<"UNSIGNED-PAYLOAD">>}]),

    ?assertEqual(Expected, Actual).

sign_v4_query_params_with_authority_well_known_port_test() ->
    AccessKeyID = <<"AKIAIOSFODNN7EXAMPLE">>,
    SecretAccessKey = <<"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY">>,
    Region = <<"us-east-1">>,
    Service = <<"s3">>,
    DateTime = {{2013, 5, 24}, {0, 0, 0}},
    Method = <<"GET">>,
    URL = <<"http://bucket.localhost:80/test.txt">>,

    Expected =
        <<"http://bucket.localhost:80/test.txt?",
        "X-Amz-Algorithm=AWS4-HMAC-SHA256&",
        "X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&",
        "X-Amz-Date=20130524T000000Z&",
        "X-Amz-Expires=86400&",
        "X-Amz-Signature=12778f8b6fc2cb5cce0fee8b218428fb8261c99a145613232d47be9aa38d1d85&",
        "X-Amz-SignedHeaders=host">>,

    Actual =
        sign_v4_query_params(AccessKeyID,
                             SecretAccessKey,
                             Region,
                             Service,
                             DateTime,
                             Method,
                             URL,
                             [{body_digest, <<"UNSIGNED-PAYLOAD">>}]),

    ?assertEqual(Expected, Actual).

format_date_long_test() ->
    Expected = <<"20210126T200815Z">>,
    Actual = format_datetime_long({{2021,1,26}, {20,8,15}}),
    ?assertEqual(Expected, Actual).

format_date_short_test() ->
    Expected = <<"20210126">>,
    Actual = format_datetime_short({{2021,1,26}, {20,8,15}}),
    ?assertEqual(Expected, Actual).

-endif.
