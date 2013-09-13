#!/usr/bin/perl -I /home/fw_audit/script/lib

use Firewall::Common qw/record open_db pass/;


sub _4001{
    #4001:detect net group
    #pass 4001:net group is non-empty
    #fail 4001:net group is empty
    
    my $tid=shift;
    my $sign=0;
    my $dbh = open_db;

    my $sth=$dbh->prepare("SELECT net_grp_name,net_ip FROM cfg_net_grp WHERE task_id=$tid")
       or die "prepare failed:".$dbh->errstr();

#    record 'DBASE',$! unless $sth->execute();
    $sth->execute() or die $!;
    
    while(my @row_ary=$sth->fetchrow_array()){
        
        if(!$row_ary[1]){
            pass $tid,4001,'fail',"地址组对象$row_ary[0]为空";
            $sign=1;
        }
    }

    if($sign == 0){pass $tid,4001,'pass',"地址组对象不为空";}

    $sth->finish();
}

#_4001 99513;
1
