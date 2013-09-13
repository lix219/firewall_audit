#!/usr/bin/perl -I /home/fw_audit/script/lib

use Firewall::Common qw/record open_db pass/;


sub _4000{
    #4000:detect host group
    #pass 4000:host group is non-empty
    #fail 4000:host group is empty
    
    my $tid=shift;
    my $sign=0;
    my $dbh = open_db;

    my $sth=$dbh->prepare("SELECT net_name,net_ip FROM cfg_net WHERE task_id=$tid")
       or die "prepare failed:".$dbh->errstr();

#    record 'DBASE',$! unless $sth->execute();
    $sth->execute() or die $!;
    
    while(my @row_ary=$sth->fetchrow_array()){
        
        if(!$row_ary[1]){
            pass $tid,4000,'fail',"地址对象$row_ary[0]为空";
            $sign=1;
        }
    }

    if($sign == 0){pass $tid,4000,'pass',"地址对象不为空";}
    $sth->finish();
}

#_4000 99513;
1
