package Firewall::Common;

use strict;

our (@ISA, @EXPORT_OK, $VERSION);

BEGIN {
    require Exporter;

    @ISA       = qw /Exporter/;
    @EXPORT_OK = qw /record open_db open_redis fetch store_r store pass/;
    $VERSION   = '1.0102';
}


sub record {
    # This subroutine record LOG

    my ($type, $message) = @_;
    # Type include: DATABASE, AUDIT, etc.

    my $date = localtime;

    open LOG, '>>', '/home/fw_audit/log/audit.log' or die $!;
    print LOG "[$date] [$type] [$message]\n";

#    print "[$date] [$type] [$message]\n";
}

# sub open_redis {
#     # This subroutine OPEN a Redis connection
#     # Return the database HANDLE if success
#     my $index = shift;
# 
#     use Redis;
# 
#     my $handle = Redis->new(server => '10.109.32.166:6379', name => 'what');
#     $handle->select($index);
# 
#     return $handle;
# }

sub open_db {
    # Open a MySQL database and return database handle;

    my $dbh;
    use DBI;
    my ($host, $user, $pass, $db) = ('10.109.32.166', 'root', '123456', 'fw_audit');
    $dbh = DBI->connect("DBI:mysql:database=$db;host=$host", $user, $pass) or
        record 'DABASE', "open db fail";
    $dbh->do("SET NAMES 'utf8'");
    $dbh;
}

sub store {
    my @p = @_;
    my $dbh = open_db;


    my $sth = $dbh->prepare(qq/
            INSERT INTO cfg_acl (task_id, acl_id, acl_num,
                acl_policy, src_area, dst_area, src_addr,
                src_port, dst_addr, dst_port, ace_state, acl_logging)
            VALUES ("$p[0]","$p[1]","$p[2]","$p[3]","$p[4]","$p[5]","$p[6]",
                "$p[7]","$p[8]","$p[9]","$p[10]","$p[11]")
            /);
    $sth->execute or record 'DBASE', "execute sql fail";
    $sth->finish;
}
# sub exist {
#     # Justice if exist a HASH in Redis that name is $key
#     my $key = shift;
# 
#     my $r = open_redis 7;
#     $r->exists($key);
# }

# sub fetch {
#     # Fetch the HASH data from Redis, the single argument is hash name
#     my $key = shift;
# 
#     my $r = open_redis 7;
#     my %hash = $r->hgetall($key);
# 
#     return %hash;
# }
# 
# sub store {
#     # Store a HASH data to Redis, the first argument is hash name, then a hash
#     my $key = shift;
#     my %hash = @_;
# 
#     my $r = open_redis 7;
#     $r->hset($key, $_, $hash{$_}, sub {}) for keys %hash;
#     $r->wait_all_responses;
# }

# sub pass {
#     # Store a result in audit, use mysql proceduce
# 
#     my $task_id = shift;
#     my $item_id = shift;
# 
#     my $dbh = open_db;
#     my $sql = "CALL Audit_$item_id($task_id)";
# 
#     my $sth = $dbh->prepare(qq/$sql/);
# 
#     $sth->execute() or record 'DBASE', "execute sql fail";
# 
#     # TODO: Maybe need store audit meta data
# 
#     record 'AUDIT', "audit $item_id";
#     $sth->finish();
# }

sub pass {
    # Store a result in

    my $tid     = shift;
    my $item_id = shift;
    my $status  = shift;
    my $message = shift;

    my $dbh = open_db;
    my $sth = $dbh->prepare(qq/INSERT INTO audit_results (task_id, item_id,
        status, message, audit_date) VALUES (?, ?, ?, ?, NOW())/);

print "INSERT INTO audit_results (task_id, item_id, status, message, audit_date) VALUES ($tid, $item_id, $status, $message, NOW())\n";

    $sth->execute($tid, $item_id, $status, $message)
        or record 'DBASE', "execute sql fail";

    # TODO: Others?
    # Suan le ba...

    $sth->finish;
}

1;

__END__


=head1 NAME

Firewall::Common - The Firewall Common Module

=head1 SYNOPSIS

  use Firewall::Common qw /store/;
  my %hash = fetch $key;    # fetch to %hash
  store $key, %hash;        # store %hash to $key

=head1 DESCRIPTION

This Module give some useful common interfaces for Firewall::Parse and
Firewall::Audit.

=cut
