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

# Kiirja a help -et, ha a -h -? --help
# kapcsolo meg van adva
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


my $rsa_pub = LoadKey($keyFile);

# Var a logsorokra
while ( my $line = <> ) {
    last if $line eq '';
    ( $sec, $microsec ) = gettimeofday;
    $line = sprintf "%d.%0.6d\t$line", $sec, $microsec, $line;
    my $log = LogLocation($logFile);
    LogDir($log);
    
    open LOG,">>","$log" || die "I can't open file in $log\n";
    while ( length $line > 0 ) {
        my $lineSlice = substr $line, 0, $rsa_pub->size() - 42, "";
        my $ciphertext = $rsa_pub->encrypt($lineSlice);
        print LOG $ciphertext;
    }
    close LOG;
}

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
    
    if ( $logFileName =~ m@%[aAbBcCdDeEFgGhHIjklmMnOpPrRsStTuUVwWxXyYzZ]@ ) {
        $retLogFileName = strftime $logFileName, localtime;
    } else {
        $retLogFileName = $logFileName;
    }

    return $retLogFileName;
}

sub LogDir {
    my $logdir = shift;
    $logdir =~ s/[^\/]*$//;
    print "$logdir\n";
    unless ( -d $logdir ) {
        my @dirs = split /\//, $logdir;
        print "@dirs\n";
        my $dir = '';
        foreach my $d ( @dirs ) {
            $dir .= "$d/";
            print "$dir\n";
            unless ( -d $dir ) {
                print "mkdir $dir\n";
                mkdir $dir, 0755 || die "I can't make directory in $logdir\n$!\n";
            }
        }
    }
}

sub help {
print<<HELP;
Usage: $0 -k -f
    -f  --log-file
    -k  --keyfile
    -h  -?  --help
HELP
}