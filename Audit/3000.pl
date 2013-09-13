#!/usr/bin/perl -I /home/fw_audit/script/lib

use Firewall::Common qw/open_db record pass/;


sub _3000 {

   #3000:detect acl policy group
    #pass 3000:
    #fail 3000:
    
    my $tid = shift;
		my $sign_3000 = 0;
    my $dbh = open_db;

    my $sth=$dbh->prepare("SELECT grp_name FROM cfg_acl_grp WHERE task_id=$tid")
       or die "prepare failed:".$dbh->errstr();

    $sth->execute() or die $!;

    my @acl_grp = ();
    while(my @row_ary=$sth->fetchrow_array()){
			print @row_ary,"\tBB\n";
			push (@acl_grp,$row_ary[0]);
    }

   #print @acl_grp;

   
      

  foreach $grp_name (@acl_grp){
      
  print $grp_name, "\tAA\n";

			my $sth_acl;
  		$sth_acl=$dbh->prepare("SELECT acl_id FROM cfg_acl WHERE acl_grp=\'$grp_name\' and task_id=\'$tid\'")
           or die "prepare failed:".$dbh->errstr();

       $sth_acl->execute() or die $!;

       my @row_ary1=$sth_acl->fetchrow_array();

       if(@row_ary1){
              last;
       }else{
#           print "HEEEEEEEEEEEEEEEEEEEEEEEEEE";
              pass $tid,3000,'fail',"访问控制规则组$grp_name为空";
							$sign_3000=1;
            }
  		$sth_acl->finish()     

  }
	

	if($sign_3000 == 0)  {
			pass $tid,3000,'pass',"访问控制规则组不为空";
	}
  
  print "OK\n";
  $sth->finish();
}

_3000 99;
#1
