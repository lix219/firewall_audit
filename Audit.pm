package Firewall::Audit;


use strict;
use warnings;
use utf8;


our (@ISA, @EXPORT_OK, $VERSION);

BEGIN {
    require Exporter;

    @ISA       = qw /Exporter/;
    @EXPORT_OK = qw /connect_redis audit subnet2range acl_schedule count_src count_dst count_ser/;
    $VERSION   = '1.0001';
}

use Firewall::Common qw /record open_db pass/;


sub connect_redis {
	my $handle = Redis->new(server => '10.109.32.166:6379', name => 'what');
	$handle->select(1);

	return $handle;
}

sub count_src{
	#get count of src addr objects in present two acl policies
	my $tid = shift;
	my $acl1 = shift;	#acl_id 1
	my $acl2 = shift;	#acl_id 2
  #  print $acl1."\t".$acl2."\n";
	#open database
	my $dbh = open_db;
	my $sth = $dbh->prepare("SELECT src_ip FROM cfg_acl_obj WHERE acl_id IN ($acl1, $acl2)")
	or die "prepare failed:".$dbh->errstr();
	$sth->execute() or die $!;

	my %src = ();	#store every src addr objects.Use hash to cover same src addr objects
	while (my @row_ary=$sth->fetchrow_array()){
		
		my @src = split /\s+/,$row_ary[0];	#src addr objects
#		my @dst = split /\s+/,$row_ary[1];	#dst addr objects
		foreach (@src){
			$src{$_} = 1;
		}
#		foreach (@dst){
#			$src{$_} = 1;
#		}
	}

	my @array = ();
	foreach my $key_src (keys %src){	
#		print "$key\n";
		#keys == different src addr objects 
		#get "count" of each src addr object, maybe a net object or a net group
		my $sth_count = $dbh->prepare("SELECT count FROM cfg_net WHERE task_id=$tid and net_name=\'$key_src\' 
									UNION SELECT count FROM cfg_net_grp WHERE task_id=$tid and net_grp_name=\'$key_src\' ")
		or die "prepare failed:".$dbh->errstr();
		$sth_count->execute() or die $!;
		while (my @count=$sth_count->fetchrow_array()){
#            print "$key:$count[0]\n";
			push @array,"对象$key_src"."被引用$count[0]次";
		}
	}
	my $res = join ',', @array;
#	print $res;
    return $res;
}

sub count_dst{
	#get count of dst addr objects in present two acl policies
	my $tid = shift;
	my $acl1 = shift;	#acl_id 1
	my $acl2 = shift;	#acl_id 2
  #  print $acl1."\t".$acl2."\n";
	#open database
	my $dbh = open_db;
	my $sth = $dbh->prepare("SELECT dst_ip FROM cfg_acl_obj WHERE acl_id IN ($acl1, $acl2)")
	or die "prepare failed:".$dbh->errstr();
	$sth->execute() or die $!;

	my %dst = ();	#store every dst addr objects.Use hash to cover same dst addr objects
	while (my @row_ary=$sth->fetchrow_array()){
		
		my @dst = split /\s+/,$row_ary[0];	#dst addr objects
#		my @dst = split /\s+/,$row_ary[1];	#dst addr objects
		foreach (@dst){
			$dst{$_} = 1;
		}
#		foreach (@dst){
#			$dst{$_} = 1;
#		}
	}

	my @array = ();
	foreach my $key_dst (keys %dst){	
#		print "$key\n";
		#keys == different dst addr objects 
		#get "count" of each dst addr object, maybe a net object or a net group
		my $sth_count = $dbh->prepare("SELECT count FROM cfg_net WHERE task_id=$tid and net_name=\'$key_dst\' 
									UNION SELECT count FROM cfg_net_grp WHERE task_id=$tid and net_grp_name=\'$key_dst\' ")
		or die "prepare failed:".$dbh->errstr();
		$sth_count->execute() or die $!;
		while (my @count=$sth_count->fetchrow_array()){
#            print "$key:$count[0]\n";
				push @array,"对象$key_dst"."被引用$count[0]次";
		}
	}
	my $res = join ',', @array;
#	print $res;
    return $res;
}

sub acl_schedule {
    #判断两条策略生效时间是否有交集

    our $tsk_id = shift;    #任务id
    my $acl_id1 = shift;
    my $acl_id2 = shift;

    #到cfg_acl表里读策略对应的时间字段
    #'always'和任意时间段有交集
    #两条策略时间字段都不是'always'，再具体去fp-schedule表里读数据比较

    #如果两条策略生效时间段有交集， return 1 ；否则return 0.

###############################################################################

    sub getDT {
        my $acl_id = shift;

        # 从数据库中获取原始时间对象
#        use DBI;
#        my ($host, $user, $pass, $db) = qw {10.109.32.166 root 123456 fw_audit};
#        my $dbh = DBI->connect("DBI:mysql:database=$db;host=$host", $user, $pass);

        use Firewall::Common qw /open_db/;
        my $dbh = open_db;

        my $sth = $dbh->prepare("SELECT `fp-schedule`.`VALUE` 
                    FROM `fp-schedule`, `cfg_acl` 
                    WHERE `fp-schedule`.`tid`=`cfg_acl`.`task_id` 
                    AND `cfg_acl`.`task_id`=? AND `cfg_acl`.`acl_id`=? 
                    AND `fp-schedule`.`STRING`=`cfg_acl`.`schedule`;");

        my $value = $sth->fetchrow() if $sth->execute($tsk_id, $acl_id);

        $sth->finish();
        $dbh->disconnect();


        # 统一为标准的时间格式
        use Time::Local;
        $value =~ s{\b(\d{2}-\d{2}-\d{2})\b}{20$1}g;

        $value =~ s{
            \b(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(:(\d{2}))?
        }{
            timelocal $7, $5, $4, $3, $2, $1;
        }xge;

        $value =~ s{
            \b(\d{2}):(\d{2})(:(\d{2}))?
        }{
            $1 * 3600 + $2 * 60 + $4;
        }xge;

        $value =~ s{^(\d+~\d+@\d{1,7})$}{0~2000000000 $1};


        # 绝对时间和循环时间的构造过程
        # 设置默认时间为 ALWAYS，除非匹配并执行下面的绝对时间和循环时间构造代码
        my $self = {
            TYPE   => "ALWAYS",
        };
        $value =~ s{
            ^(\d+)~(\d+)$
        }{
            $self = {
                TYPE   => "A",      # 类型 A 代表绝对时间
                START  => $1,
                END    => $2,
            };
        }xge;

        $value =~ s{
            ^(\d+)~(\d+)[ ](\d+)~(\d+)@(\d{1,7})$
        }{
            $self = {
                TYPE   => "R",      # 类型 R 代表循环时间
                START  => $1,
                END    => $2,
                TSTART => $3,
                TEND   => $4,
                WEEK   => $5,
            };
        }xge;

        return %$self;
    }

    my %dt1 = getDT $acl_id1;
    my %dt2 = getDT $acl_id2;

    printf "%-10s%-16d%-16d%-10d%-10d%-10d\n", $dt1{TYPE}, $dt1{START}, $dt1{END}, $dt1{TSTART}, 
                $dt1{TEND}, $dt1{WEEK};
    printf "%-10s%-16d%-16d%-10d%-10d%-10d\n", $dt2{TYPE}, $dt2{START}, $dt2{END}, $dt2{TSTART}, 
                $dt2{TEND}, $dt2{WEEK};
    # 遇到系统内设的 always 时间对象，直接返回有交集
    return 1 if $dt1{TYPE} eq "ALWAYS";
    return 1 if $dt2{TYPE} eq "ALWAYS";

    if ($dt1{TYPE} eq "A" and $dt2{TYPE} eq "A") {
        return 0 if $dt1{END} < $dt2{START} or $dt2{END} < $dt1{START};
        return 1;
    }
    elsif ($dt1{TYPE} eq "R" and $dt2{TYPE} eq "A") {
        my %tmp = %dt1;
        %dt1 = %dt2;
        %dt2 = %tmp;
        print "$dt1{TYPE} $dt2{TYPE}\n";
    }
    sub cmpWeek {
        my ($w1, $w2) = @_;
        foreach (1 ..7) {
            return 1 if $w1 =~ m/$_/ and $w2 =~ m/$_/;
        }
        0;
    }
    # 判断绝对时间与循环时间对象之比较
    if ($dt1{TYPE} eq "A" and $dt2{TYPE} eq "R") {
        return 0 if $dt1{END} < $dt2{START} or $dt2{END} < $dt1{START};
        return 1 if ($dt1{END} - $dt1{START}) > 604800;
        # 晚上完成下面的任务
        # 一周以内的时间比较
        my $week;
        my $sdok = (7, 1, 2, 3, 4, 5, 6)[(localtime $dt1{START})[6]];
        my $edok = (7, 1, 2, 3, 4, 5, 6)[(localtime $dt1{END})[6]];
        print "$sdok $edok\n";
        if ($sdok < $edok) {
            $week = join "", $sdok .. $edok;
        }
        else {
            $week = join "", $sdok .. 7, 1 .. $edok;
        }
        print "$week\n";
        # 比较连个跟对象的星期元素是否相交
        print "$week $dt2{WEEK}\n";
        return 0 unless cmpWeek $week, $dt2{WEEK};
        my $stime = (localtime $dt1{START})[2] * 3600 + (localtime $dt1{START})[1] * 60 + 
                (localtime $dt1{START})[0];
        my $etime = (localtime $dt1{END})[2] * 3600 + (localtime $dt1{END})[1] * 60 + 
                (localtime $dt1{END})[0];
        # 比较时分秒
        return 0 if $etime < $dt2{TSTART} or $dt2{TEND} < $stime;
        return 1;
    }
    elsif ($dt1{TYPE} eq "R" and $dt2{TYPE} eq "R") {
        return 0 if $dt1{END} < $dt2{START} or $dt2{END} < $dt1{START};
        # 这里好像缺了点什么
        return 0 if $dt1{TEND} < $dt2{TSTART} or $dt2{TEND} < $dt1{TSTART};
        return 0 unless cmpWeek $dt1{WEEK}, $dt2{WEEK};
        return 0 if $dt1{TEND} < $dt2{TSTART} or $dt2{TEND} < $dt1{TSTART};
        return 1;
    }
}




sub subnet2range{
    my $subnet = shift;
    #my @subnet = 192.168.1.1/24;
    my @mask_ary;    
    my $mask;
    my @snet = split /\//,$subnet;
    my $ipaddr = $snet[0];

    if ($snet[1] =~ /\./){  #ip/mask
        $mask = $snet[1];
    }
    else {  #CIDR
        my $m = int ($snet[1] / 8);
        for (1..$m){
            push @mask_ary,255;
        }
        my $n = $snet[1] % 8;
        my $k = 7 - $n;
        my $s;
        for (0..$k) {
            $s += 2**$_;
        }
        push @mask_ary,255-$s;

        my $a = $#mask_ary;
        if ($a < 3){
            for ($a..3){
                $mask_ary[$_] = 0;
            }
        } 
        $mask = join '.', @mask_ary;
        #print $mask;    
    }                          
        
    my (@msk, @nsk);
    @msk = split /\./, $mask;
    ### @msk
    $nsk[$_] = 255 - $msk[$_] foreach (0..3);
    my $nask = join '.', @nsk;

    my (@ip1, @ip2);
    push @ip1, int((split /\./, $ipaddr)[$_]) & int((split /\./, $mask)[$_]) foreach (0..3);
    push @ip2, int((split /\./, $ipaddr)[$_]) | int((split /\./, $nask)[$_]) foreach (0..3);

    my $ip1 = join '.', @ip1;
    my $ip2 = join '.', @ip2;

    return "$ip1\-$ip2";
		print "IP Range: $ip1-$ip2";
		print "finished\n";
}


sub count_ser{
	#get count of ser objects in present two acl policies
	my $tid = shift;
	my $acl1 = shift;	#acl_id 1
	my $acl2 = shift;	#acl_id 2
  #print $acl1."\t".$acl2."\n";
	#open database
	my $dbh = open_db;
	my $sth = $dbh->prepare("SELECT srv FROM cfg_acl_obj WHERE acl_id IN ($acl1, $acl2)")
	or die "prepare failed:".$dbh->errstr();
	$sth->execute() or die $!;

	my %ser = ();	#store every ser objects.Use hash to cover same ser objects
	while (my @row_ary=$sth->fetchrow_array()){
		
		my @ser = split /\s+/,$row_ary[0];	#ser objects
		foreach (@ser){
			$ser{$_} = 1;
		}
	}

	my @array = ();
	foreach my $key_ser (keys %ser){	
#		print "$key\n";
		#keys == different ser objects 
		#get "count" of each ser object, maybe a net object or a net group
		my $sth_count = $dbh->prepare("SELECT DISTINCT count FROM cfg_defser_grp WHERE task_id=$tid and defsrv_name=\'$key_ser\' 
									UNION SELECT count FROM cfg_ser_grp WHERE task_id=$tid and ser_grp_name=\'$key_ser\' ")
		or die "prepare failed:".$dbh->errstr();
		$sth_count->execute() or die $!;
		while (my @count=$sth_count->fetchrow_array()){
#            print "$key:$count[0]\n";
				push @array,"对象$key_ser"."被引用$count[0]次";
		}
	}
	my $res = join ',', @array;
#	print $res;
    return $res;
}



#sub rule_srv_telnet_connection(){
#
#   #2000:detect telnet status
#    #pass 2000:telnet on
#    #fail 2000:telnet off
#    our $tid;
#
#    my $dbh = open_db;
#
#    my $sth=$dbh->prepare("SELECT srv_id,srv_status FROM cfg_srv WHERE srv_type=0 and task_id=$tid")
#       or die "prepare failed:".$dbh->errstr();
#
#    record 'DBASE', $! unless $sth->execute;
#
#    while(my @row_ary=$sth->fetchrow_array){
#            
#        print $row_ary[1];
#
#        pass $tid, 2000,'pass', "" if $row_ary[1] == 0;
#        pass $tid, 2000,'fail', "" if $row_ary[1] == 1;
#    }
#    
#    $sth->finish();
#}
#

sub audit {
    my $tid = shift;
    my @audit_items = @_;

    print "TASK ID+++++++++++++++++$tid\n";
    print "ADUIT ID++++++++++++++++++++++++@audit_items\n";

    # Auditing item by item_id
    foreach (@audit_items) {
        # require a absoult path
	require "/home/fw_audit/script/lib/Firewall/Audit/$_.pl"; 
        print "____________________________PRINT $_\n";
	no strict 'refs';
	"_$_"->($tid);
    }
    return 1;
}

# sub audit {
# 
#     my $task_id = shift;
#     my @audit_items = @_;
# 
#     # Auditing item by item_id
#     foreach my $item (@audit_items) {
#         pass $task_id, 4009 if $item == 4009;
#         pass $task_id, 4010 if $item == 4010;
#     }
# 
#     return 1;
# }

1;

__END__


=head1 NAME


1;

__END__


=head1 NAME

Firewall::Audit - The Firewall Audit Module

=head1 SYNOPSIS

  use Firewall::Audit qw /audit/;

  audit @cats;              # audit @cats this

=head1 DESCRIPTION

This Module give you a pretty interface to audit the information fetch
from the database.

=cut
