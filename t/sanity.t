use strict;
use warnings FATAL => 'all';

use Apache::Test;
use Apache::TestRequest qw(GET);

plan tests => 1;


# move this to utils
sub bake_cookie {
    use Crypt::KeyDerivation 'pbkdf2';
    use Crypt::Misc 'encode_b64', 'decode_b64';
    use Crypt::Mac::HMAC 'hmac_hex';
    use Crypt::Mode::CBC;

    my ( $ip, $ua, $score, $uuid, $vid, $time ) = @_;
    my $data = $time . '0' . $score . $uuid . $vid . $ua;

    my $password        = 'perimeterx';
    my $salt            = '12345678123456781234567812345678';
    my $iteration_count = 1000;
    my $hash_name       = undef;                              #default is SHA256
    my $len             = 48;

    my $km = pbkdf2( $password, $salt, $iteration_count, $hash_name, $len );
    my $key = substr( $km, 0,  32 );
    my $iv  = substr( $km, 32, 48 );

    my $m         = Crypt::Mode::CBC->new('AES');
    my $hmac      = hmac_hex( 'SHA256', $password, $data );
    my $plaintext = '{"t":'
      . $time
      . ', "s":{"b":'
      . $score
      . ', "a":0}, "u":"'
      . $uuid
      . '", "v":"'
      . $vid
      . '", "h":"'
      . $hmac . '"}';
    my $ciphertext = $m->encrypt( $plaintext, $key, $iv );

    my $cookie = encode_b64($salt) . ":" . 1000 . ":" . encode_b64($ciphertext);
    return '_px=' . $cookie;
}

my $time = ( time() + 360 ) * 1000;

my $cookie = bake_cookie(
	"1.2.3.4",
	"libwww-perl/0.00",
	"20",
	"57ecdc10-0e97-11e6-80b6-095df820282c",
	"vid",
	$time
);

my $res = GET '/index.html', 'real-ip' => '1.2.3.4', 'Cookie' => $cookie; 
ok $res->code == 200
