#!/usr/bin/perl -I /home/fw_audit/script/lib

use Firewall::Common qw/record open_db pass/;


sub _3100{
    #3100:detect acl service limit
    #pass 3100:service is limited
    #fail 3100:no service limit
    
    my $tid=shift;
		my $sign=0;
    my $dbh = open_db;

    my $sth=$dbh->prepare("SELECT acl_id,srv FROM cfg_acl WHERE task_id=$tid")
       or die "prepare failed:".$dbh->errstr();

#    record 'DBASE',$! unless $sth->execute();
    $sth->execute() or die $!;
    
    while(my @row_ary=$sth->fetchrow_array()){
        
        if($row_ary[1] =~ /any/i){
            pass $tid,3100,'fail',"访问控制策略$row_ary[0]服务为任意";
						$sign=1;
        }
    }
		if($sign ==0) {pass $tid,3100,'pass',"访问控制策略服务不为任意";}
    $sth->finish();
}

#_3100 99513;
1
