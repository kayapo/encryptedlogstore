#!/usr/bin/perl -w
use strict;
use Crypt::OpenSSL::RSA;
use Getopt::Long;
use Convert::PEM;
use MIME::Base64;

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

my $options = GetOptions(
                         "k|keyfile=s" => \$keyFile,
                         "f|infile=s" => \$inFile
                         );

unless ( defined $keyFile && defined $inFile ) {
    print STDERR "-k --keyfile and -f --infile is required!\n";
    exit 1;
}

$keyFile = LoadKey($keyFile);

my $rsa_priv = Crypt::OpenSSL::RSA->new_private_key($keyFile) || die "I can't use key!\n\t$!\n";

open ENCFILE, "<", $inFile || die "I don't open input file:\n\t$!\n";
while ( (read ENCFILE, $encData, $rsa_priv->size()) != 0 ) {
    $plainLine = $rsa_priv->decrypt($encData);
    print $plainLine;
}
close ENCFILE;

print "\n";

sub LoadKey {
    my $file = shift;
    my $retVal;
    
    open KEYFILE,"<",$keyFile || die "I can't open key file:\n\t$!\n";
    my @keyLines = <KEYFILE>;
    my $keyContent = join "", @keyLines;
    close KEYFILE;

    if ( $keyContent =~ /DEK-Info/m ) {
        use Term::ReadKey;
        ReadMode 2;
        print "Type passphrase for key file $file: ";
        ReadMode 0;
        
        my $password = ReadLine;
        chomp $password;
        
        my $pem = Convert::PEM->new(
                                  Name => 'RSA PRIVATE KEY',
                                  ASN  => qq( RSAPrivateKey SEQUENCE {version INTEGER, n INTEGER, e INTEGER, d INTEGER, p INTEGER, q INTEGER, dp INTEGER, dq INTEGER, iqmp INTEGER}
                                 ));
    
        my $pkey =
            $pem->decode(Content => $keyContent, Password => $password);
    
        return(undef) unless ($pkey); # Decrypt failed.
        $retVal = $pem->encode(Content => $pkey);
    } else {
        $retVal = $keyContent;
    }
}
