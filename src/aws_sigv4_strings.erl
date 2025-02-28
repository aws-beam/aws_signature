%% Based on:
%% https://github.com/aws/smithy-go/blob/main/aws-http-auth/internal/v4/strings.go
-module(aws_sigv4_strings).

-export([ base16/1
        , uri_encode/1
        ]).

-spec uri_encode(binary()) -> binary().
uri_encode(String) ->
  <<(uri_encode_byte(Byte)) || <<Byte>> <= String>>.

-spec uri_encode_byte(byte()) -> binary().
uri_encode_byte(Byte)
  when $A =< Byte, Byte =< $Z;
       $a =< Byte, Byte =< $z;
       $0 =< Byte, Byte =< $9;
       Byte =:= $-;
       Byte =:= $.;
       Byte =:= $_;
       Byte =:= $~;
       Byte =:= $/ ->
  <<Byte>>;
uri_encode_byte(Byte) ->
  Hi = (Byte bsr 4) band 16#0F,
  Lo = Byte band 16#0F,
  <<"%", (tohex_upper(Hi)), (tohex_upper(Lo))>>.

-spec base16(binary()) -> binary().
base16(String) ->
  << <<(tohex_lower((Byte bsr 4) band 16#0F)), (tohex_lower(Byte band 16#0F))>> || <<Byte>> <= String>>.

-spec tohex_upper(byte()) -> byte().
tohex_upper(N) when N < 10 -> N + $0;
tohex_upper(N) -> N + ($A - 10).

-spec tohex_lower(byte()) -> byte().
tohex_lower(N) when N < 10 -> N + $0;
tohex_lower(N) -> N + ($a - 10).
