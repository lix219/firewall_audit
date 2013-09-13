#!/usr/bin/perl -I /home/fw_audit/script/lib

use Firewall::Common qw/record open_db pass/;


sub _3103{
    #3103:detect acl source interface
    #pass 3103:source interface != any 
    #fail 3103:source interface == any
    
    my $tid=shift;
	my $sign=0;
    my $dbh = open_db;

    my $sth=$dbh->prepare("SELECT acl_id,interface FROM cfg_acl WHERE task_id=$tid")
       or die "prepare failed:".$dbh->errstr();
#    record 'DBASE',$! unless $sth->execute();
    $sth->execute() or die $!;    
    while(my @row_ary=$sth->fetchrow_array()){        
        if($row_ary[1] =~ /any/i){
            pass $tid,3103,'fail',"访问控制策略$row_ary[0]接口为任意";
			$sign=1;
        }
    }
	if($sign == 0)	{pass $tid,3103,'pass',"访问控制策略接口不为任意";}
    $sth->finish();
}

#_3103 4;
1
