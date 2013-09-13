#!/usr/bin/perl -I /home/fw_audit/script/lib
use Firewall::Common qw/record open_db pass/;


sub _4004{
    #4004:detect acl dst ip
    #pass 4004:dst ip != any 
    #fail 4004:dst ip == any
    
    my $tid=shift;

    my $dbh = open_db;

    my $sth=$dbh->prepare("SELECT dst_addr FROM cfg_acl WHERE task_id=$tid")
       or die "prepare failed:".$dbh->errstr();

#    record 'DBASE', $! unless $sth->execute;
    $sth->execute() or die $!;

    while(my $row_ary=$sth->fetchrow_array()){
        if($row_ary =~ /any/i){
            
            pass $tid,4004,'fail','目的ip地址不能为any' ;
        }else{
            pass $tid,4004,'pass','通过';
        }
    }
    $sth->finish();
}

#_4004 1894;
1
