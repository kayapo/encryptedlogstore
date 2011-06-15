#!/usr/bin/perl -w
use strict;
use Crypt::OpenSSL::RSA;
use Getopt::Long;
use Convert::PEM;

Crypt::OpenSSL::RSA->import_random_seed();

# Fuggosegek:
#    libcrypt-openssl-random-perl
#    libcrypt-openssl-rsa-perl
#    libcrypt-openssl-bignum-perl
#    libconvert-pem-perl

my $keyFile;
my $inFile;
my $encData;
my $plainLine;
my $help;

my $options = GetOptions(
                         "k|keyfile=s" => \$keyFile,
                         "f|infile=s" => \$inFile,
                         "h|?|help" => \$help
                         );

# Kiirja a help -et, ha a -h -? --help kapcsolo meg van adva
if ( defined $help ) {
    &help;
    exit 0;
}

# Kilep ha a -k --keyfile es a -f --infile nincs megadva
unless ( defined $keyFile && defined $inFile ) {
    print STDERR "-k --keyfile and -f --infile is required!\n";
    exit 1;
}

# Betolti a privat kulcsot ezzel lehet elolvasni a logfilet
$keyFile = LoadKey($keyFile);
my $rsa_priv = Crypt::OpenSSL::RSA->new_private_key($keyFile) || die "I can't use key!\n\t$!\n";

# Megnyitja a logfilet es $rsa_prive->size() meretu chunk-okban olvassa
# $rsa_prive->size() a kulcs merete
open ENCFILE, "<", $inFile || die "I don't open input file:\n\t$!\n";
while ( (read ENCFILE, $encData, $rsa_priv->size()) != 0 ) {
    $plainLine = $rsa_priv->decrypt($encData);
    print $plainLine;
}
close ENCFILE;

exit 0;

# Ezzel tolti be a kulcsot
sub LoadKey {
    my $file = shift;
    my $retVal;
    
    open KEYFILE,"<",$keyFile || die "I can't open key file:\n\t$!\n";
    my @keyLines = <KEYFILE>;
    my $keyContent = join "", @keyLines;
    close KEYFILE;

    # Ha a kulcs jelszoval vedett,bekeri a jeszot
    if ( $keyContent =~ /DEK-Info/m ) {
        use Term::ReadKey;
        # Kikapcsolja a kimenetet
        ReadMode 2;
        # majd bekeri a jelszot
        print "Type passphrase for key file $file: ";
        my $password = ReadLine;
        ReadMode 0;
        chomp $password;
        
        # Letrehozza az RSA objektumot
        my $pem = Convert::PEM->new(
                                  Name => 'RSA PRIVATE KEY',
                                  ASN  => qq( RSAPrivateKey SEQUENCE {version INTEGER, n INTEGER, e INTEGER, d INTEGER, p INTEGER, q INTEGER, dp INTEGER, dq INTEGER, iqmp INTEGER}
                                 ));
        # A bekert jelszoval kinyitja a kulcsot
        my $pkey = $pem->decode(Content => $keyContent, Password => $password);
        
        # Ha a jelszó hibas kilep
        die "Wrong password!" unless ($pkey);
        $retVal = $pem->encode(Content => $pkey);
    } else {
        $retVal = $keyContent;
    }
}

# Help meszazs
sub help {
print<<HELP;
$0 read encrypted log lines from file.
The encryption use PEM formated RSA private key.
Strongly recommended to password protect the key!

Usage: $0 -k <public.pem> -f <location_of.log>
    -f  --log-file  Logfile destination. The strftime escape format supported
    -k  --keyfile   RSA public key location
    -h  -?  --help  This message
    
    Key generation:
    ===============
    
    Password shielded (strongly recommended) private key:
        /usr/bin/openssl genrsa -aes256 -out private.pem 2048
    or
        /usr/bin/openssl genrsa -des3 -out private.pem 2048
    Afterwards, the public key:
        /usr/bin/openssl rsa -in private.pem -out public.pem -outform PEM -pubout
HELP
}
