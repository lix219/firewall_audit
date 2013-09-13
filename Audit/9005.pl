#!/usr/bin/perl -I /home/fw_audit/script/lib
use Firewall::Common qw/record open_db pass/;


sub _4005{
    #4005:detect if acl dst ip is in C-section
    #pass 4005:dst ip isn't in C-section
    #fail 4005:dst ip is in C-section
    
    my $tid = shift;

    my $dbh = open_db;
print "tid => $tid\n";
    my $sth=$dbh->prepare("SELECT cfg_acl_id,dst_addr FROM cfg_acl WHERE task_id=\'$tid\'")
       or die "prepare failed:".$dbh->errstr();

#    record 'DBASE', $! unless $sth->execute;
    $sth->execute() or die $!;

    while(my @row_ary=$sth->fetchrow_array()){
        if($row_ary[1]  =~ /(\.\d+)(\.\d+)(\.\d+)/){
            if($`>191 && $`<224){
                pass $tid,4005,'fail','目的ip地址不能是C段' ;
            }else{
                pass $tid,4005,'pass','通过';
            }
        }
    }
    $sth->finish();
}

#_4005 1894;
1
