#!/usr/bin/perl -I /home/fw_audit/script/lib

use Firewall::Common qw/record open_db pass/;

sub _3001 {
    #detect the state of acl policy 
    #pass:state is on
    #fail:state is off
    my $tid=shift;
		my $sign=0;
    my $dbh = open_db;

    my $sth=$dbh->prepare("SELECT acl_id,policy_state FROM cfg_acl WHERE task_id=$tid")
       or die "prepare failed:".$dbh->errstr();

    #record 'DBASE', $! unless $sth->execute;

    $sth->execute() or die $!;

    while(my @row_ary=$sth->fetchrow_array()){
        if($row_ary[1] ==0){
        pass $tid,3001,'fail',"访问控制策略$row_ary[0]未启用";
				$sign=1;
        }        
    }

		if($sign == 0)	{pass $tid,3001,'pass','访问控制策略已启用';}
    $sth->finish();
}

#_3001 99513;
1
