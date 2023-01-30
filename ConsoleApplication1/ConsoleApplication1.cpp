#include <iostream>
#include <string>
#include <fstream>
#include "picosha2/picosha2.h"

#include "libRSASign/md5.h"
#include "libRSASign/RSAKeyProducer.h"
#include "libRSASign/Number.h"
#include "libRSASign/RSASignature.h"

int main() {

	//first, we generate keys for moderators and game.
	Key t_PK, t_SK;
	Key q_PK, q_SK;
	
	//genrating keys takes some time,but only one pair for each moderators
	//The signature lib is not an optimized one, i want to use the c lib from microsoft, its fast and secure enough. https://github.com/microsoft/qTESLA-Library. But I constantly get the LNK2001 error, unresolved symble error, I can't fix it quickly, so I choose this one for demonstration.
	RSAKeyProducer t(32), q(32);
	t.produceKey(t_PK, t_SK);    // generate sender's key
	q.produceKey(q_PK, q_SK);	// generate receiver's key
	//once generated, the keys should be saved to file. but for a demo, it's ok.
	//TODO: Save keys to files.
	//t_SK, q_PK should be kept a secret by moderators.
	//q_SK, t_PK are public keys that shipped with the game.
	
	
	//now comes the Identification string part. not much work to do except show messages to user
	std::string steamID = "<SteamUserID:xxxxxxxxx>"; // this is the runner's id
	std::string game_record_unverified = "<RecordTime><GameDetails><LeaderboardNameOrIdentifier>";//this is actually the info submitted to lb
	std::cout << "Game Record Submitted to lb after each match:" << std::endl << "\t" << game_record_unverified << std::endl << std::endl;
	steamID += game_record_unverified;//combine id and record for sha256
	std::vector<unsigned char> hash(picosha2::k_digest_size);
	picosha2::hash256(steamID.begin(), steamID.end(), hash.begin(), hash.end());
	std::string tempSHA256 = picosha2::bytes_to_hex_string(hash.begin(), hash.end());//just a temp str used later
	game_record_unverified += tempSHA256; //append the hash to the record string.
	
	//This is the message that shpws to the user in console or chat window.
	std::cout << "If you want this run to be verified, you should submit your video proof together with this Idenfication String to forum for verification:" << std::endl << "\t" << game_record_unverified << std::endl << std::endl;
	
	//afer the community verification, moderators have to use another cmdline tool to sign on the user record. this is done outside the game.
	RSASignature w;
	std::string signed_string_from_moderator;
	w.encryptSign(t_SK, q_PK, game_record_unverified, signed_string_from_moderator);//since the sha256 takes the steamID into account, there is no need to contain ID in the game_record_unverified. no priviacy issues.
	std::string temp = signed_string_from_moderator; //this is just a temp string that is used later
	//this is the verified string that returns to the user
	signed_string_from_moderator = game_record_unverified + signed_string_from_moderator;
	std::cout << "this is the verified string that returns to the user:" << std::endl << "\t" << signed_string_from_moderator << std::endl << std::endl;

	//after the user gets the verified string, he will put it in a game menu's textbox. then the game do these things.
	// 1. split the signed_string_from_moderator to game record and the signature, i dont do it here for convince. I assume it is splited into game_record_unverified and temp
	//2. verify whether it is a vaild string from moderator
	std::string md5;
	w.decryptSign(q_SK, t_PK, temp, md5);//get the md5 info stored in the signature
	MD5 md(game_record_unverified);
	std::string md5_origin = md.md5();//get the md5 value of the readable game record
	//here we just do a manual check.
	std::cout << "Signed record text MD5:\t\t" << md5 << std::endl;
	std::cout << "Original record text MD5:\t" << md5_origin << std::endl << std::endl;

	//if one modifies the signed string, for example. the first char
	std::string modified_record = game_record_unverified;
	modified_record[0] = 'x';
	std::cout<<"If one modifies the signed string, for example. the first char:" << std::endl << "\t" << modified_record + temp << std::endl << std::endl;
	w.decryptSign(q_SK, t_PK, temp, md5);//get the md5 info stored in the signature
	//let's see what the md5 results
	MD5 md1(modified_record);
	md5_origin = md1.md5();//get the md5 value of the readable game record
	//here we just do a manual check.
	std::cout << "Signed record text MD5:\t\t" << md5 << std::endl;
	std::cout << "Modified record text MD5:\t" << md5_origin << std::endl << std::endl;


	//now that the string is verified, then we need to check if this record belongs to the input user
	//1.get steamID of the input user
	std::string steamID_record_owner = "<SteamUserID:xxxxxxxxx>";
	std::string steamID_record_thief = "<SteamUserID:yyyyyyyyy>";
	//2.extract record and sha256 strings. here i assume it is extracted and stored in tmp_record and tempSHA256
	std::string tmp_record = "<RecordTime><GameDetails><LeaderboardNameOrIdentifier>";
	//3. verify the sha256
	steamID_record_owner += tmp_record;
	steamID_record_thief += tmp_record;
	std::vector<unsigned char> hash_owner(picosha2::k_digest_size);
	std::vector<unsigned char> hash_thief(picosha2::k_digest_size);
	picosha2::hash256(steamID_record_owner.begin(), steamID_record_owner.end(), hash_owner.begin(), hash_owner.end());
	picosha2::hash256(steamID_record_thief.begin(), steamID_record_thief.end(), hash_thief.begin(), hash_thief.end());
	std::string tempSHA256_owner = picosha2::bytes_to_hex_string(hash_owner.begin(), hash_owner.end());
	std::string tempSHA256_thief = picosha2::bytes_to_hex_string(hash_thief.begin(), hash_thief.end());
	std::cout << "We can use sha256 to check whether the record belongs to the inputting user:" << std::endl;
	std::cout << "SHA256 stored in verified string:\t" << tempSHA256 << std::endl;
	std::cout << "SHA256 using owner's steamID:\t" << tempSHA256_owner << std::endl;
	std::cout << "SHA256 using thief's steamID:\t" << tempSHA256_thief << std::endl << std::endl;
	//4. override leaderboard
	// SteamAPICall_t UploadLeaderboardScore( SteamLeaderboard_t hSteamLeaderboard, ELeaderboardUploadScoreMethod eLeaderboardUploadScoreMethod, int32 nScore, const int32 *pScoreDetails, int cScoreDetailsCount );
	// by specifying eLeaderboardUploadScoreMethod = k_ELeaderboardUploadScoreMethodForceUpdate
	// the record could be manually overrided.
	// considering we have two steps of verification, this could prevent most of the users to modify as they wish. but cheaters with source code modified could by pass this verification. anyway, without this, they can also use this function to override record.
	// to override a record, the hSteamLeaderboard must be specified, we can use <LeaderboardNameOrIdentifier> in the string to get it.


	return 0;
}


