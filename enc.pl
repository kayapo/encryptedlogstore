#!/usr/bin/perl -w
use strict;
use Crypt::OpenSSL::RSA;
use Getopt::Long;
use Time::HiRes qw( gettimeofday );
use POSIX qw( strftime );

Crypt::OpenSSL::RSA->import_random_seed();

# Fuggosegek:
#    libcrypt-openssl-random-perl
#    libcrypt-openssl-rsa-perl
#    libcrypt-openssl-bignum-perl
#
# Kulcs generalas:
#   Jelszoval vedett RSA privat kulcs -> /usr/bin/openssl genrsa -aes256 -out private.pem 2048
#   Publikus kulcs -> /usr/bin/openssl rsa -in private.pem -out public.pem -outform PEM -pubout
#
# Logfile formatum, strftime formatalt string
#   Info -> man strftime
#
# Licence:
#   This script licenced under:
#   BSD, Apache, GPLv2, LGPLv2 use your prefered!

my $sec;
my $microsec;
my $line;
my $logFile;
my $help;
my $keyFile;

# A parancssori kapcsolok elolvasasa
my $options = GetOptions(
                         "f|log-file=s" => \$logFile,
                         "h|?|help" => \$help,
                         "k|keyfile=s" => \$keyFile
                         );

# Kiirja a help -et, ha a -h -? --help kapcsolo meg van adva
if ( defined $help ) {
    &help;
    exit 0;
}

# Kilep ha a -k --keyfile nincs megadva
unless ( defined $keyFile ) {
    print STDERR "Keyfile is not set!\n";
    exit 1;
}

# Kilep, ha  a -f --log-file nincs megadva
unless ( defined $logFile ) {
    print STDERR "--log-file or --date-formated-logfiles required!\n";
    exit 1;
}

# Betolti a publikus kulcsot ezzel fogja titkositani a logsorokat.
my $rsa_pub = LoadKey($keyFile);

# Var a logsorokra
while ( my $line = <> ) {
    # Ures sornal kilep a program
    last if $line eq '';
    
    # Itt all elo a microtime stamp egyelore a gep sajat orajabol
    ( $sec, $microsec ) = gettimeofday;
    $line = sprintf "%d.%0.6d\t$line", $sec, $microsec, $line;
    
    # Eloallitja a logfile helyet es nevet majd leelenorzi, hogy letezik-e?
    my $log = LogLocation($logFile);
    LogDir($log);
    
    # Megnyitja a logot hozzairasra
    open LOG,">>","$log" || die "I can't open file in $log\n";
    # kiirja a logfileba a logsort amivel eppen dolgozik akkora
    # chunk-okban ami meg bele fer a kulcsba
    while ( length $line > 0 ) {
        my $lineSlice = substr $line, 0, $rsa_pub->size() - 42, "";
        my $ciphertext = $rsa_pub->encrypt($lineSlice);
        print LOG $ciphertext;
    }
    close LOG;
}
exit 0;

# Betolti a kulcsfilet
sub LoadKey {
    my $keyFile = shift;
    
    open KEYFILE,"<",$keyFile || die "I can't open key file $keyFile\n$!\n";
    my @keyLines = <KEYFILE>;
    $keyFile = join "", @keyLines;
    close KEYFILE;
    
    return Crypt::OpenSSL::RSA->new_public_key($keyFile);
}

# Visszaadja a logfile helyet
sub LogLocation {
    my $logFileName = shift;
    my $retLogFileName = '';
    
    # Ha a logfile neveben, strftime escape van
    # itt alakitja vissza az escape-elest
    if ( $logFileName =~ m@%[aAbBcCdDeEFgGhHIjklmMnOpPrRsStTuUVwWxXyYzZ]@ ) {
        $retLogFileName = strftime $logFileName, localtime;
    } else {
        $retLogFileName = $logFileName;
    }

    return $retLogFileName;
}

# Ellenorzi, hogy az utvonal, ahol a logfile lesz
# letezik-e es ha nem akkor letrehozza
sub LogDir {
    my $logdir = shift;
    $logdir =~ s/[^\/]*$//; # dirname
    unless ( -d $logdir ) {
        my @dirs = split /\//, $logdir;
        my $dir = '';
        foreach my $d ( @dirs ) {
            $dir .= "$d/";
            
            # Letrehozza a konyvtarat 0755 joggal, ezen kellene kicsit
            # csiszolni.
            unless ( -d $dir ) {
                mkdir $dir, 0755 || die "I can't make directory in $logdir\n$!\n";
            }
        }
    }
}

# Help meszazs
sub help {
print<<HELP;
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
