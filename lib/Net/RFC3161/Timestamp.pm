package Net::RFC3161::Timestamp;

# ABSTRACT: Utility functions to request RFC3161 timestamps

use strict;
use warnings;
use Exporter 'import';
use Carp;
use HTTP::Request;
use LWP::UserAgent;

our @EXPORT    = qw(list_tsas);
our @EXPORT_OK = qw(dump_ts);


=head2 list_tsas

 my $l = list_tsas();

Returns a hash reference. The keys correspond to shortnames of timestamping
authorities ("dfn.de", "verisign"), the values to the access URLs.

=cut

my %TSAs = (
    ## RFC 3161 compatible:
    "certum" => "http://time.certum.pl/",
    "comodo" => "http://timestamp.comodoca.com/",
    "digicert" => "http://timestamp.digicert.com/",
    "globalsign" => "http://timestamp.globalsign.com/scripts/timestamp.dll",
    "quovadis" => "http://tsa01.quovadisglobal.com/TSS/HttpTspServer",
    "startcom" => "http://tsa.startssl.com/rfc3161",
    "verisign" => "http://sha256timestamp.ws.symantec.com/sha256/timestamp",
    # national
    "dfn.de" => "http://zeitstempel.dfn.de",
    "ermis.gov.gr" => "http://timestamp.ermis.gov.gr/TSS/HttpTspServer",
    "e-guven.com" => "http://zd.e-guven.com/TSS/HttpTspServer",
    "ssc.lt" => "http://gdlqtsa.ssc.lt/TSS/HttpTspServer",
);

sub list_tsas() {
  return \%TSAs;
}


sub dump_ts {
    my ($kind, $buf) = @_;

    if (open(my $fh, "|-", "openssl", "ts", "-$kind",
                                            "-in" => "/dev/stdin",
                                            "-text"))
    {
        $fh->binmode;
        $fh->write($buf);
        $fh->close;
    } else {
        _warn("failed to spawn 'openssl ts'");
    }
}

sub make_request_for_file {
    my ($file, $hash_algo, $policy) = @_;
    $hash_algo //= "sha256";

    my @cmd = ("openssl", "ts", "-query",
                                "-data" => $file,
                                "-$hash_algo",
                                "-cert");
    if ($policy) {
        push @cmd, ("-policy" => $policy);
    }

    if (open(my $fh, "-|", @cmd)) {
        my $req_buf;
        $fh->binmode;
        $fh->read($req_buf, 4*1024);
        $fh->close;
        return $req_buf;
    } else {
        croak("failed to spawn 'openssl ts'");
    }
}

sub post_request {
    my ($req_buf, $tsa_url) = @_;

    my $ua = LWP::UserAgent->new;

    my $req = HTTP::Request->new("POST", $tsa_url);
    $req->protocol("HTTP/1.0");
    $req->header("Content-Type" => "application/timestamp-query");
    $req->header("Accept" => "application/timestamp-reply,application/timestamp-response");
    $req->content($req_buf);

    my $res = $ua->request($req);
    if ($res->code == 200) {
        my $ct = $res->header("Content-Type");
        if ($ct eq "application/timestamp-reply"
            || $ct eq "application/timestamp-response")
        {
            return $res->content;
        } else {
            croak("server returned wrong content-type '$ct'");
        }
    } else {
        croak("server returned error '".$res->status_line."'");
    }
}

sub write_response_to_file {
    my ($res_buf, $file) = @_;

    if (open(my $fh, ">", $file)) {
        $fh->binmode;
        $fh->write($res_buf);
        $fh->close;
    } else {
        croak("could not open '$file': $!");
    }
}


1;
