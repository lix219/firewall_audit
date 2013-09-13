#!/usr/bin/perl -I /home/fw_audit/script/lib

use Firewall::Common qw/record open_db pass/;

sub _3002 {
    #detect the number of manager_max_login
    #pass:the number <= 5
    #fail:the number > 5
    my $tid=shift;
		my $sign=0;
    my $dbh = open_db;

    my $sth=$dbh->prepare("SELECT acl_id,acl_policy FROM cfg_acl WHERE task_id=$tid")
       or die "prepare failed:".$dbh->errstr();

    #record 'DBASE', $! unless $sth->execute;

    $sth->execute() or die $!;

    while(my @row_ary=$sth->fetchrow_array()){
        if($row_ary[1] ==2){
        pass $tid,3002,'fail',"访问控制策略$row_ary[0]动作为collect";
				$sign=1;
        }
    }
		if($sign==0)	{pass $tid,3002,'pass','访问控制策略动作不为collect';}

    $sth->finish();
}

#_3002 99513;
1
