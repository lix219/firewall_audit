#!/usr/bin/perl -I /home/fw_audit/script/lib

use Firewall::Common qw/record open_db pass/;


sub _3102{
    #3102:detect acl source ip
    #pass 3102:source ip != any 
    #fail 3102:source ip == any
    
    my $tid=shift;
		my $sign=0;
    my $dbh = open_db;

    my $sth=$dbh->prepare("SELECT acl_id,dst_addr FROM cfg_acl WHERE task_id=$tid")
       or die "prepare failed:".$dbh->errstr();

#    record 'DBASE',$! unless $sth->execute();
    $sth->execute() or die $!;
    
    while(my @row_ary=$sth->fetchrow_array()){
        
        if($row_ary[1] =~ /any/i){
            pass $tid,3102,'fail',"访问控制策略$row_ary[0]目的地址为任意";
						$sign=1;
        }
    }
		if($sign == 0)	{pass $tid,3102,'pass',"访问控制策略目的地址不为任意";}

    $sth->finish();
}

#_3102 99513;
1
