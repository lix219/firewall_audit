#!/usr/bin/perl -I /home/fw_audit/script/lib

use Firewall::Common qw/open_db record pass/;

sub _2004 {

   #2004:detect web_manage timeout
    #pass 2004:timeout is set
    #fail 2004:no timeout
    
    my $tid=shift;
		my $sign_2004 = 0;
    my $dbh = open_db;

    my $sth=$dbh->prepare("SELECT timeout FROM cfg_srv WHERE srv_type=2 and srv_status=1 and task_id=$tid")
       or die "prepare failed:".$dbh->errstr();

    $sth->execute() or die $!;

    while(my @row_ary=$sth->fetchrow_array()){
            
        #print "@row_ary\n";
        if( !($row_ary[0] < 600 && $row_ary[0] > 0) ){
            pass $tid, 2004,'fail', 'WEB管理超时限制在10分钟以上';
						$sign_2004 = 1;
        }else{
#            pass $tid, 2004,'fail', 'WEB管理超时限制在10分钟以上';
        }
    }
 		if ($sign_2004 == 0){   
            pass $tid, 2004,'pass', 'WEB管理超时限制在10分钟以内';
        }
    print "OK\n";
    $sth->finish();
}

#_2004 99513;
1
