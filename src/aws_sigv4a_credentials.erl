%% Based on:
%% https://github.com/aws/smithy-go/blob/main/aws-http-auth/sigv4a/credentials.go
-module(aws_sigv4a_credentials).

-export([ derive/1
        ]).

%% exported for tests
-export([ derive_private_key/1
        ]).

-include("aws_sigv4_internal.hrl").

-spec derive(aws_sigv4_internal:credentials()) -> {ok, binary()} | {error, any()}.
derive(Credentials) ->
  #credentials{access_key_id = AKID} = Credentials,
  case persistent_term:get(?MODULE, false) of
    {AKID, PrivateKey} -> {ok, PrivateKey};
    _ ->
      case derive_private_key(Credentials) of
        {ok, PrivateKey} = Result ->
          persistent_term:put(?MODULE, {AKID, PrivateKey}),
          Result;
        {error, _Reason} = Error -> Error
      end
  end.

%% See "Deriving a signing key for SigV4a" subsection of:
%% https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html#derive-signing-key
-spec derive_private_key(aws_sigv4_internal:credentials()) -> {ok, binary()} | {error, any()}.
derive_private_key(Credentials) ->
  NMinus2 = p256_n() - 2,
  #credentials{access_key_id = AKID, secret_access_key = SK} = Credentials,
  InputKey = << <<"AWS4A">>/binary, SK/binary>>,
  derive_private_key(_Counter = 1, NMinus2, AKID, InputKey).

-spec derive_private_key(byte(), non_neg_integer(), binary(), binary()) -> {ok, binary()} | {error, any()}.
derive_private_key(Counter, NMinus2, AKID, InputKey) ->
  case Counter < 255 of
    true ->
      Context = <<AKID/binary, Counter>>,
      Key = derive_hmac_key(InputKey, Context),
      KeyNrBits = byte_size(Key) * 8,
      KeyNrBits = 256, % assert
      <<C:KeyNrBits/big>> = Key,
      case C > NMinus2 of
        true -> derive_private_key(Counter + 1, NMinus2, AKID, InputKey);
        false -> {ok, <<(C + 1):KeyNrBits/big>>}
      end;
    false -> {error, exhausted_single_byte_external_counter}
  end.

-spec p256_n() -> non_neg_integer().
p256_n() ->
  115792089210356248762697446949407573529996955224135760342422259061068512044369.

-spec p256_bitsize() -> non_neg_integer().
p256_bitsize() ->
  256.

-spec derive_hmac_key(binary(), binary()) -> binary().
derive_hmac_key(Key, Context) ->
  BitLen = p256_bitsize(),
  N = ((BitLen + 7) div 8) div sha256_size(),
  Label = <<"AWS4-ECDSA-P256-SHA256">>,
  FixedInput = <<Label/binary, 16#00, Context/binary, BitLen:32/big>>,
  %% INV: N == 1, so no loop needed
  N = 1, % assert
  Input = <<1:32/big, FixedInput/binary>>,
  hmac_sha256(Key, Input).

-spec hmac_sha256(binary(), binary()) -> binary().
hmac_sha256(Key, Data) ->
  crypto:mac(hmac, sha256, Key, Data).

-spec sha256_size() -> non_neg_integer().
sha256_size() ->
  32.
