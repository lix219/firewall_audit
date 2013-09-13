#!/usr/bin/perl -I /home/fw_audit/script/lib

use Firewall::Common qw/open_db record pass/;
sub	for_each_port
{
		my $g_key = shift;	#$g_key	name:type:port1:port2
		my $type = shift;
		my $lower_bound = shift;
		my $upper_bound = shift;
		my @arr = split /:/,$g_key;
		print "****************$arr[0],$lower_bound, $upper_bound*****************\n";

		if(($type==6) || ($type==17)){
			if ($upper_bound>=1521 && $lower_bound<=1521){
				#print "审计组$g_name 范围 $lower_bound-$upper_bound\n";
				if (exists $ser_4104{$arr[0]} ){
					print "$arr[0] exist\n";
      			}else{
      				$ser_4104{$arr[0]} = 1;
      				pass $tid, 4104,'fail', "自定义服务目的端口包含1521端口 $arr[0]:[$lower_bound-$upper_bound]";
      			}
			}
		}
}

sub _4104 {
    our $tid=shift;
    our %ser_4104 = ();
    my $dbh = open_db;
    my $sth=$dbh->prepare("SELECT defsrv_name, defsrv_type, defsrv_from_port,defsrv_to_port FROM  cfg_defser_grp WHERE task_id=$tid")
       or die "prepare failed:".$dbh->errstr();
    $sth->execute() or die $!;;
	our %global_map;#key=custormize group name  value=array which stores two integer representing the range
		
    while(my @row_ary=$sth->fetchrow_array()){
            
        #print "@row_ary\n";
			#print "$row_ary[0]\n";
			#my $g_name=$row_ary[1];
			#my @g_range= split(/-/,$row_ary[2]);
			my @g_range= ($row_ary[1], $row_ary[2], $row_ary[3]);
			#print "$g_name $g_range\n";
			my $g_key = join ':',$row_ary[0],@g_range;	#$g_key	name:type:port1:port2

			$global_map{$g_key}=\@g_range;
			#print "@g_range\n"
            #print "@row_ary\n";
    }
    foreach my $key (keys %global_map) {
			@arr=@{$global_map{$key}};
			delete($global_map{$key});
			for_each_port $key, @arr;
			#	foreach my $item (@{$global_map{$key}})
			#	{print "$item "};
			#	print "\n";
		}
    print "OK\n";
    $sth->finish();
}


#_4104 2015;
1
