#!/usr/bin/perl -I /home/fw_audit/script/lib

use Firewall::Common qw/record open_db pass/;


sub _4002{
    #4002:detect service group
    #pass 4002:service group is non-empty
    #fail 4002:service group is empty
    
    my $tid=shift;
    my $sign=0;
    my $dbh = open_db;

    my $sth=$dbh->prepare("SELECT ser_grp_name,ser_member FROM cfg_ser_grp WHERE task_id=$tid")
       or die "prepare failed:".$dbh->errstr();

#    record 'DBASE',$! unless $sth->execute();
    $sth->execute() or die $!;
    
    while(my @row_ary=$sth->fetchrow_array()){
        
        if(!$row_ary[1]){
            pass $tid,4002,'fail',"服务组对象$row_ary[0]为空";
            $sign=1;
        }
    }

    if($sign == 0){pass $tid,4002,'pass',"服务组对象不为空";}
    $sth->finish();
}

#4002 99513;
1
