%% @private
-module(aws_signature_utils).

-export([hmac_sha256/2,
         hmac_sha256_hexdigest/2,
         sha256_hexdigest/1,
         binary_join/2,
         base16/1,
         hex/2,
         parse_url/1,
         uri_encode_path/1,
         rebuilds_url_with_query_params/2
        ]).

%% @doc Creates an HMAC-SHA256 hexdigest for `Key' and `Message'.
-spec hmac_sha256_hexdigest(binary(), binary()) -> binary().
hmac_sha256_hexdigest(Key, Message) ->
    base16(hmac_sha256(Key, Message)).

%% @doc Creates an HMAC-SHA256 binary for `Key' and `Message'.
-spec hmac_sha256(binary(), binary()) -> binary().
hmac_sha256(Key, Message) ->
    crypto_hmac(sha256, Key, Message).

%% @doc Creates a SHA256 hexdigest for `Value'.
-spec sha256_hexdigest(binary()) -> binary().
sha256_hexdigest(Value) ->
    base16(crypto:hash(sha256, Value)).

%% @doc Joins binary values using the specified separator.
-spec binary_join(Parts :: [binary()], Separator :: binary()) -> binary().
binary_join([], _) -> <<"">>;
binary_join([H], _) -> H;
binary_join([H1, H2 | T], Sep) ->
    binary_join([<<H1/binary, Sep/binary, H2/binary>> | T], Sep).

%% @doc Encodes binary data with base 16 encoding.
-spec base16(binary()) -> binary().
base16(Data) ->
    << <<(hex(N div 16, lower)), (hex(N rem 16, lower))>> || <<N>> <= Data >>.

%% @doc Converts an integer between 0 and 15 into a hexadecimal char.
-spec hex(0..15, lower | upper) -> byte().
hex(N, _Case) when N >= 0, N < 10 ->
    N + $0;
hex(N, lower) when N < 16 ->
    N - 10 + $a;
hex(N, upper) when N < 16 ->
    N - 10 + $A.

%% @doc Parses the given URL, returning the host, path and query components.
%%
%% The parsed `host' is normalized, such that it includes the port, if and
%% only if a not-standard port (80 or 443) is present in the URL.
%%
%% An alternative to `uri_string:parse/1' to support OTP below 21.
-spec parse_url(binary()) -> #{host => binary(), path => binary(), query => binary()}.
-ifdef(OTP_RELEASE). % OTP >= 21
  parse_url(URL) when is_binary(URL) ->
    #{host := Host, path := Path} = P = uri_string:parse(URL),

    Port = format_port(maps:get(port, P, undefined)),
    NormalizedHost = <<Host/binary, Port/binary>>,

    #{host => NormalizedHost, path => Path, query => maps:get(query, P, <<>>)}.

  format_port(undefined) -> <<>>;
  format_port(80) -> <<>>;
  format_port(443) -> <<>>;
  format_port(Port) ->
      FinalPort = list_to_binary(integer_to_list(Port)),
      <<":", FinalPort/binary>>.

-else. % OTP < 21
  parse_url(URL) when is_binary(URL) ->
    %% From https://datatracker.ietf.org/doc/html/rfc3986#appendix-B
    {ok, Regex} = re:compile("^(([a-z][a-z0-9\\+\\-\\.]*):)?(//([^/?#]*))?([^?#]*)(\\?([^#]*))?(#(.*))?", [caseless]),

    case re:run(URL, Regex, [{capture, all, binary}]) of
        {match, [_, _1, _2, _3, Authority, Path, _6, Query | _]} ->
            #{host => authority_to_host(Authority), path => Path, query => Query};
        {match, [_, _1, _2, _3, Authority, Path | _]} ->
            #{host => authority_to_host(Authority), path => Path, query => <<"">>};
        _ ->
            #{host => <<"">>, path => <<"">>, query => <<"">>}
    end.

  authority_to_host(Authority) ->
    Authority1 = remove_trailing(Authority, <<":80">>),
    remove_trailing(Authority1, <<":443">>).

  remove_trailing(Binary, Sufix) ->
    SufixSize = byte_size(Sufix),
    PrefixSize = byte_size(Binary) - SufixSize,
    case Binary of
      <<Prefix:PrefixSize/binary, Sufix/binary>> -> Prefix;
      _Else -> Binary
    end.
-endif.

-spec rebuilds_url_with_query_params(binary(), [{binary(), binary()}]) -> binary().
rebuilds_url_with_query_params(OriginalURL, QueryParams) ->
    %% Similar parse_url/1, but just split the URL in all until query params, and ignore the rest.
    URL =
        case binary:split(OriginalURL, <<"?">>) of
            [UrlUntilQuery, _ExistingQuery] -> UrlUntilQuery;
            [UrlUntilQuery] -> UrlUntilQuery
        end,
    Pairs = [binary_join([Key, Value], <<"=">>) || {Key, Value} <- QueryParams],
    NewQuery = binary_join(Pairs, <<"&">>),
    binary_join([URL, NewQuery], <<"?">>).


%% @doc URI-encodes the given path.
%%
%% Escapes all characters except for "/" and the unreserved
%% characters listed in https://tools.ietf.org/html/rfc3986#section-2.3
%%
%% See the UriEncode function in the docs: https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
-spec uri_encode_path(binary()) -> binary().
uri_encode_path(Path) when is_binary(Path) ->
    << (uri_encode_path_byte(Byte)) || <<Byte>> <= Path >>.

-spec uri_encode_path_byte(byte()) -> binary().
uri_encode_path_byte($/) -> <<"/">>;
uri_encode_path_byte(Byte)
    when $0 =< Byte, Byte =< $9;
        $a =< Byte, Byte =< $z;
        $A =< Byte, Byte =< $Z;
        Byte =:= $~;
        Byte =:= $_;
        Byte =:= $-;
        Byte =:= $. ->
    <<Byte>>;
uri_encode_path_byte(Byte) ->
    H = Byte band 16#F0 bsr 4,
    L = Byte band 16#0F,
    <<"%", (aws_signature_utils:hex(H, upper)), (aws_signature_utils:hex(L, upper))>>.

%% This can be simplified if we drop support for OTP < 21
%% This can be removed if we drop support for OTP < 23
-ifdef(OTP_RELEASE). % OTP >= 21
    -if(?OTP_RELEASE >= 23).
        -define(USE_CRYPTO_MAC_4, true).
    -else.
        -undef(USE_CRYPTO_MAC_4).
    -endif.
-else. % OTP < 21
    -undef(USE_CRYPTO_MAC_4).
-endif.

-spec crypto_hmac(atom(), binary(), binary()) -> binary().
-ifdef(USE_CRYPTO_MAC_4).
    crypto_hmac(Sha, Key, Data) -> crypto:mac(hmac, Sha, Key, Data).
-else.
    crypto_hmac(Sha, Key, Data) -> crypto:hmac(Sha, Key, Data).
-endif.

%%====================================================================

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

%% sha256_hexdigest/1 returns a SHA256 hexdigest for an empty value.
sha256_hexdigest_with_empty_value_test() ->
    ?assertEqual(
        <<"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855">>,
        sha256_hexdigest(<<"">>)).

%% sha256_hexdigest/1 returns a SHA256 hexdigest for a non-empty body.
sha256_hexdigest_test() ->
    ?assertEqual(
        <<"315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3">>,
        sha256_hexdigest(<<"Hello, world!">>)).

%% hmac_sha256/2 returns a SHA256 HMAC for a message.
hmac_sha256_test() ->
    ?assertEqual(
        <<110, 158, 242, 155, 117, 255, 252,  91,
          122, 186, 229,  39, 213, 143, 218, 219,
          47, 228,  46, 114,  25,   1,  25, 118,
          145, 115,  67,   6,  95,  88, 237,  74>>,
        hmac_sha256(<<"key">>, <<"message">>)).

%% hmac_sha256_hexdigest/2 returns an HMAC SHA256 hexdigest for a message.
hmac_sha256_hexdigest_test() ->
    ?assertEqual(
        <<"6e9ef29b75fffc5b7abae527d58fdadb2fe42e7219011976917343065f58ed4a">>,
        hmac_sha256_hexdigest(<<"key">>, <<"message">>)).

%% binary_join/2 joins a list of binary values, separated by a separator
%% character, into a single binary value
binary_join_test() ->
    ?assertEqual(
        binary_join([<<"a">>, <<"b">>, <<"c">>], <<",">>),
        <<"a,b,c">>).

%% binary_join/2 correctly joins binary values with a multi-character
%% separator
binary_join_with_multi_character_separator_test() ->
    ?assertEqual(
        binary_join([<<"a">>, <<"b">>, <<"c">>], <<", ">>),
        <<"a, b, c">>).

%% binary_join/2 converts a list containing a single binary into the
%% binary itself.
binary_join_with_single_element_list_test() ->
    ?assertEqual(binary_join([<<"a">>], <<",">>), <<"a">>).

%% binary_join/2 returns an empty binary value when an empty list is given
binary_join_with_empty_list_test() ->
    ?assertEqual(binary_join([], <<",">>), <<"">>).

%% parse_url/1 returns empty path and query if none is present
parse_url_with_root_url_test() ->
    ?assertEqual(
        parse_url(<<"https://example.com">>),
        #{path => <<"">>, query => <<"">>, host => <<"example.com">>}).

%% parse_url/1 parses just path
parse_url_with_just_path_test() ->
    ?assertEqual(
        parse_url(<<"https://example.com/te%20st/path">>),
        #{query => <<"">>, path => <<"/te%20st/path">>, host => <<"example.com">>}).

%% parse_url/1 parses just query
parse_url_with_just_query_test() ->
    ?assertEqual(
        parse_url(<<"https://example.com?a=1&b&c=2">>),
        #{host => <<"example.com">>, path => <<"">>, query => <<"a=1&b&c=2">>}).

%% parse_url/1 parses both path and query in a full URL
parse_url_with_full_url_test() ->
    ?assertEqual(
        parse_url(<<"https://example.com/path/to/file/?a=1&b&c=2#fragment">>),
        #{host => <<"example.com">>, path => <<"/path/to/file/">>, query => <<"a=1&b&c=2">>}).

%% parse_url/1 omits standard port number in the host
parse_url_with_standard_port() ->
    ?assertEqual(
        parse_url(<<"https://example.com:443">>),
        #{host => <<"example.com">>, path => <<"">>, query => <<"">>}).

%% parse_url/1 includes non-standard port number in the host
parse_url_with_non_standard_port() ->
    ?assertEqual(
        parse_url(<<"https://example.com:3000">>),
        #{host => <<"example.com:3000">>, path => <<"">>, query => <<"">>}).

%% uri_encode_path/1 keeps forward slash and unreserved characters unchanged
uri_encode_path_with_forward_slash_test() ->
    ?assertEqual(uri_encode_path(<<"/a1/~_-./">>), <<"/a1/~_-./">>).

%% uri_encode_path/1 escapes reserved characters
uri_encode_path_with_reserved_characters_test() ->
    ?assertEqual(uri_encode_path(<<"/a+b%c[d] e:f/">>), <<"/a%2Bb%25c%5Bd%5D%20e%3Af/">>).

%% rebuilds_url_with_query_params/2 correctly assambles a new URL
rebuilds_url_with_query_params_test() ->
  OriginalURL =
      <<"https://example.com/path?existing_param=value&another_one=true#i-will-be-ignored">>,

  Actual =
      rebuilds_url_with_query_params(OriginalURL,
                                     [{<<"new_param">>, <<"new_value">>}]),

  Expected = <<"https://example.com/path?new_param=new_value">>,
  ?assertEqual(Expected, Actual).

-endif.
