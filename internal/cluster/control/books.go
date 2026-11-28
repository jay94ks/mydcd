// SPDX-License-Identifier: Apache-2.0

package control

// books is the one list of Raft books that dispatch through the Book
// registry (book.go). A new book is one file declaring its Book value plus
// one line here. Every book reduces through its Book; actions, admission and
// events of the books added in S2 still use the older per-key branches in
// CommandKey, AdmitModule, authorizeChange and ProjectEvents (R18 S3).
var books = []Book{
	nodeShellBook,
	clusterFirewallBook,
	vpsBook,
	ownedVPSBook,
	volumeSharesBook,
	imageCacheBook,
	tunnelReconnectBook,
	compactBook,
	clusterBackupBook,
	certificatesBook,
	credentialsBook,
	ingressManagementBook,
	imageBuildBook,
	registryMaintenanceBook,
	externalRegistriesBook,
	registriesBook,
	lifecycleBook,
	nodeStorageBook,
	vaultBook,
	appsBook,
	volumesBook,
	resourcesBook,
	membersBook,
	catalogBook,
}
