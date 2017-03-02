package Apache::TestModPerimeterX;

$Apache::TestModPerimeterX::Version = '0.1';

use strict;
use warnings;

sub new {
    #my $class = @_;
    my $class = shift;
    print "class: $class\n";
    my $self = {};
    bless $self, $class;
    return $self;
    #return bless \%args, $class;
}

sub bake_cookie {
    my( $self ) = @_;

    #my $self = shift;

    use Crypt::KeyDerivation 'pbkdf2';
    use Crypt::Misc 'encode_b64', 'decode_b64';
    use Crypt::Mac::HMAC 'hmac_hex';
    use Crypt::Mode::CBC;

    my ( $ip, $ua, $score, $uuid, $vid, $time ) = @_;
    my $data = $time . '0' . $score . $uuid . $vid . $ip . $ua;

    my $password        = "perimeterx";
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
    return 'Cookie: _px=' . $cookie;
};

my $c = Apache::TestModPerimeterX->new;
print "c: $c\n";
my $co= $c->bake_cookie("123", "PhantomJS", "abc", "vid", "mytime");
print "cookie: $co\n";

#print "cookie: $co\n";

1;

