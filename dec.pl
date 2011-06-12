#!/usr/bin/perl -w
use strict;
use Crypt::OpenSSL::RSA;
use Getopt::Long;

Crypt::OpenSSL::RSA->import_random_seed();

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

# Betolti a kulcsfilet
open KEYFILE,"<",$keyFile || die "I don't open key file:\n\t$!\n";
my @keyLines = <KEYFILE>;
$keyFile = join "", @keyLines;
close KEYFILE;
my $rsa_priv = Crypt::OpenSSL::RSA->new_private_key($keyFile) || die "I don't use key!\n\t$!\n";

open ENCFILE, "<", $inFile || die "I don't open input file:\n\t$!\n";
while ( (read ENCFILE, $encData, $rsa_priv->size()) != 0 ) {
    $plainLine = $rsa_priv->decrypt($encData);
    print $plainLine;
}
close ENCFILE;

print "\n";
