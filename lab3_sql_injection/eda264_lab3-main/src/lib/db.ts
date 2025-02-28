import Database from 'better-sqlite3';
import md5 from 'md5';

const db = new Database('db.db');
db.exec(
	'CREATE TABLE IF NOT EXISTS Table_Users (' +
		'UID Integer Primary Key Autoincrement, ' +
		'Username TEXT NOT NULL,                ' +
		'Password TEXT NOT NULL,                ' +
		'SID TEXT)'
);

db.exec(
	'CREATE TABLE IF NOT EXISTS Table_Comments (' +
		'UID Integer Primary Key Autoincrement, ' +
		'Timestamp TEXT NOT NULL,               ' +
		'User Integer NOT NULL,                 ' +
		'Html TEXT)'
);

export function checkUserPass(username: string, password: string): { UID: number; Error?: Error } {
	const hash = md5(password);
	const command = 'SELECT UID FROM Table_Users WHERE Username=? AND Password=?';
	try {
		const uid = db.prepare(command).get(username, hash) as { UID: number };
		return uid;
	} catch (e) {
		return { UID: 0, Error: e as Error };
	}
}

export function getUserFromSessionID(sid: string): { Username: string; Error?: Error } {
	const command = 'SELECT Username FROM Table_Users WHERE SID=?';
	try {
		const username = db.prepare(command).get(sid) as { Username: string };
		return username;
	} catch (e) {
		return { Username: '', Error: e as Error };
	}
}

export function getUIDFromSessionID(sid: string): number {
	const command = 'SELECT UID FROM Table_Users WHERE SID=?';
	const uid = db.prepare(command).get(sid) as { UID: number };
	return uid.UID;
}

export function addUserSessionID(uid: number, sid: string): boolean {
	const command = 'UPDATE Table_Users SET SID=? WHERE UID=?';
	try {
		db.prepare(command).run(sid, uid);
		return true;
	} catch {
		return false;
	}
}

export function addComment(sid: string, comment: string): { done: boolean; Error?: Error } {
	const uid = getUIDFromSessionID(sid);
	const day = new Date();
	const stmt = db.prepare('INSERT INTO Table_Comments (Timestamp, User, Html) VALUES( ?, ?, ?)');
	try {
		stmt.run(day.toDateString(), uid, comment);
		return { done: true };
	} catch (e) {
		return { done: false, Error: e as Error };
	}
}

export function getComments(): [
	{ Timestamp: string; Username: string; Html: string }
] {
	const command =
		'SELECT Timestamp, Username, Html FROM ' +
		'Table_Comments INNER JOIN Table_Users ON ' +
		'Table_Comments.User=Table_Users.UID';
	const result = db.prepare(command).all() as [
		{ Timestamp: string; Username: string; Html: string }
	];
	return result;
}

