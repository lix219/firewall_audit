#!/usr/bin/perl -I /home/fw_audit/script/lib

use Firewall::Common qw/record open_db pass/;

sub _1001 {
    #detect the number of max_online_adm
    #pass:the number <= 10
    #fail:the number > 10
    my $tid=shift;
		my $sign_1001 = 0;
    my $dbh = open_db;

    my $sth=$dbh->prepare("SELECT m_online FROM cfg_dev_users WHERE task_id=$tid")
       or die "prepare failed:".$dbh->errstr();

    #record 'DBASE', $! unless $sth->execute;

    $sth->execute() or die $!;

    while(my @row_ary=$sth->fetchrow_array()){
				print @row_ary;"1000GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG\tBB\n";
        if($row_ary[0] > 10){
        pass $tid,1001,'fail',"在线管理员的最大数目为$row_ary[0],超过10";
				$sign_1001 = 1;
        }else{        
       # pass $tid,1001,'pass',"在线管理员的最大数目为$row_ary[0]";
        }
    }
				if ($sign_1001 ==0){
        		pass $tid,1001,'pass',"在线管理员的最大数目设置合理";
				}
        
    $sth->finish();
}

#_1001 99513;
1
