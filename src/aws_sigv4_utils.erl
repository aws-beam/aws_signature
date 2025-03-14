-module(aws_sigv4_utils).

-export([ binaries_join/2
        , format_time_long/1
        , format_time_short/1
        , sha256/1
        ]).

-spec binaries_join(binary(), [binary()]) -> binary().
binaries_join(Separator, Binaries) ->
  iolist_to_binary(lists:join(Separator, Binaries)).

-spec format_time_long(calendar:datetime()) -> binary().
format_time_long({{YY, MM, DD}, {H, M, S}}) ->
  format_timestamp(format_date(YY, MM, DD), H, M, S).

-spec format_time_short(calendar:datetime()) -> binary().
format_time_short({{YY, MM, DD}, _}) ->
  format_date(YY, MM, DD).

-spec format_date(non_neg_integer(), non_neg_integer(), non_neg_integer()) -> binary().
format_date(YY, MM, DD) ->
  YB = integer_to_binary(YY),
  MB = maybe_pad(MM),
  DB = maybe_pad(DD),
  <<YB/binary, MB/binary, DB/binary>>.

-spec format_timestamp(binary(), non_neg_integer(), non_neg_integer(), non_neg_integer()) -> binary().
format_timestamp(Date, H, M, S) ->
  HB = maybe_pad(H),
  MB = maybe_pad(M),
  SB = maybe_pad(S),
  <<Date/binary, "T", HB/binary, MB/binary, SB/binary, "Z">>.

-spec maybe_pad(non_neg_integer()) -> binary().
maybe_pad(X) when X < 10 ->
  <<"0", (integer_to_binary(X))/binary>>;
maybe_pad(X) ->
  integer_to_binary(X).

-spec sha256(binary()) -> binary().
sha256(Binary) ->
  crypto:hash(sha256, Binary).
