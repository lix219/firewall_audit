#!usr/in/perl
#
my $file = "/a";
my $tid = shift @ARGV;
open CONF, "<", $file;

    my %user_info;
while (<CONF>) {
    if (/user administrator (\S+) local secret .*/) {

#    use DBI;
#    my ($host, $user, $pass, $db) = qw /10.109.32.166 root 123456 fw_audit/;
#
#    print "***********************(((((((($1------------------------";
#    # set a global database handle
#    my $h = DBI->connect("dbi:mysql:database=$db;host=$host", $user, $pass);
#    $h->do("set names utf8");
        use Firewall::Common qw/open_db/;
        my $h = open_db;
        my $s = $h->prepare(qq/insert into `fp-auth`(tid,NAME,AUTH_IP) values("$tid","$1","0.0.0.0\/0")/);

        $s->execute or die $!;
        $s->finish;
    }
        if (/(?<=\n)user administrator (\S+) authorized-address (first|second|third) (\S+)/) {
            $user_info{$1} .= "$3 ";
            print "________________  $1  _______  $3\n";
            print $user_info{$1};
        }
}







    foreach (keys %user_info) {
        print $_;
        print " ____ $user_info{$_} ___";
        print "(((((((((($tid";
#    use DBI;
#    my ($host, $user, $pass, $db) = qw /10.109.32.166 root 123456 fw_audit/;
#
#    # set a global database handle
#    my $h = DBI->connect("dbi:mysql:database=$db;host=$host", $user, $pass);
#    $h->do("set names utf8");
        use Firewall::Common qw/open_db/;
        my $h = open_db;
        my $s = $h->prepare(qq/update `fp-auth` set AUTH_IP="$user_info{$_}" where tid="$tid" and NAME="$_"/);

        $s->execute or die $!;
        $s->finish;
    }
