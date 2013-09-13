#!/usr/bin/perl

use warnings;
use DBI;

sub _9008 {
	my $task_id = shift;

	my $host = 'localhost';
	my $port = "3306";
	my $user = 'root';
	my $password = '123456';
	my $dbname = 'fw_audit';

	my $database = "DBI:mysql:$dbname:$host:$port";
	my $dbh = DBI->connect($database, $user, $password);
	$dbh->do("SET NAMES 'utf8'");

print "Execute 9008\n";
	# 获取4006对应的警告内容
	my $warning_sql = "SELECT description FROM audit_items WHERE item_id=9008";
	my $warning_result = $dbh->prepare($warning_sql);
	$warning_result->execute() or die "Can't execute: $dbh->errstr";
	my $warning_row = $warning_result->fetchrow_array;
	my $warning = $warning_row;
	$warning_result->finish;

	my $sql = "SELECT dst_port FROM cfg_acl WHERE task_id=$task_id";
	my $result = $dbh->prepare($sql);

	$result->execute() or die "Can't execute: $dbh->errstr";

	my $sign;
	while (my $row = $result->fetchrow_array) {
		$sign = 0;
		my @arr = split / +/, $row;
		foreach (@arr) {
			if ($_ =~ /TELNET/i) {
				my $insert_sql = "INSERT INTO audit_results VALUES ($task_id, null, 9008, 'fail', \'$warning\', NOW())";
				print "$insert_sql\n";
				my $insert_result = $dbh->prepare($insert_sql);
				$insert_result->execute() or die "Can't execute:  $dbh->errstr";
				$sign = 1;
				last;
			}
		}

		if ($sign == 0)	{
			my $insert_sql = "INSERT INTO audit_results VALUES ($task_id, null, 9008, 'pass', '敏感端口23未向外对互联网开放', NOW())";
			print "$insert_sql\n";
			my $insert_result = $dbh->prepare($insert_sql);
			$insert_result->execute() or die "Can't execute:  $dbh->errstr";
		}
	}

	$result->finish;
	$dbh->disconnect;
}

#_9008 1;
1
