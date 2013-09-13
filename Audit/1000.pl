#!/usr/bin/perl -I /home/fw_audit/script/lib

use Firewall::Common qw/record open_db pass/;

sub _1000 {
		my $sign_1000 = 0;
		print "1000GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG\tBB\n";
    #detect the number of manager_max_login
    #pass:the number <= 5
    #fail:the number > 5
    my $tid=shift;

    my $dbh = open_db;

    my $sth=$dbh->prepare("SELECT DISTINCT m_login FROM cfg_dev_users WHERE task_id=$tid")
       or die "prepare failed:".$dbh->errstr();

    #record 'DBASE', $! unless $sth->execute;

    $sth->execute() or die $!;

    while(my @row_ary=$sth->fetchrow_array()){
        if($row_ary[0] > 5){
        		pass $tid,1000,'fail',"同一管理员最大并发管理数为$row_ary[0],超过5";
						$sign_1000 = 1;
        }else{       
#        		pass $tid,1000,'pass',"同一管理员最大并发管理数为$row_ary[0]";
				}	
		}
		if($sign_1000 ==0){
				pass $tid,1000,'pass',"同一管理员最大并发管理数设置合理";
		}
    $sth->finish();
}

#_1000 170;
1
