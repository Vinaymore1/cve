const simpleGit = require('simple-git');
const fs = require('fs');
const path = require('path');

const git = simpleGit(path.join(__dirname, '../../cvelistV5')); // Adjust the path to your repo directory

async function checkGitDiff() {
    try {
        // Fetch the latest changes from the remote repository
        await git.fetch();

        // Check if the local branch is behind the remote
        const status = await git.status();
        if (status.behind > 0) {
            console.log(`Your branch is ${status.behind} commit(s) behind the remote. Pulling latest changes...`);

            const pullResult = await git.pull();
            console.log('Pulling the latest changes...');
            console.log('Files updated in pull:', pullResult.files);  // Log which files were updated
        } else {
            console.log("Your branch is up to date with the remote.");
        }

        // Now check for git diff against the last commit
        const changedFiles = await git.diffSummary(['HEAD@{1}']); // Compare with the last commit

        if (changedFiles.files.length === 0) {
            console.log("No changes detected in git diff after the pull.");
		} else {
			const dirPath = path.join(process.cwd(), '.tmp');

			if (!fs.existsSync(dirPath)) {
				fs.mkdirSync(dirPath, { recursive: true });
				console.log('Directory created:', dirPath);
			} else {
				console.log('Directory already exists:', dirPath);
			}

			const changedFilesList = changedFiles.files.map(file => file.file).join('\n');

            // Write to a file named "changes"
            fs.writeFile('.tmp/changes', changedFilesList, (err) => {
                if (err) {
                console.error('Error writing to file', err);
                } else {
                console.log('Changed files have been written to changes');
                }
            });
            console.log("Changed files after the pull:", changedFiles.files.map(file => file.file)); // Log the changed files
        }

        return changedFiles.files.map(file => file.file);
    } catch (error) {
        console.error("Error checking git diff:", error);
        throw error; // Rethrow the error to handle it in the calling function
    }
}

module.exports = {
    checkGitDiff
};



// const simpleGit = require('simple-git');
// const path = require('path');

// const git = simpleGit(path.join(__dirname, '../cvelistV5')); // Adjust the path to your repo directory

// async function checkGitDiff() {
//     try {
//         // Fetch the latest changes from the remote repository
//         await git.fetch();

//         // Check if the local branch is behind the remote
//         const status = await git.status();
//         if (status.behind > 0) {
//             console.log(`Your branch is ${status.behind} commit(s) behind the remote. Pulling latest changes...`);

//             const pullResult = await git.pull();
//             console.log('Pulling the latest changes...');
//             console.log('Files updated in pull:', pullResult.files);  // Log which files were updated
//         } else {
//             console.log("Your branch is up to date with the remote.");
//         }

//         // Now check for git diff against the last commit
//         const changedFiles = await git.diffSummary(['HEAD@{1}']); // Compare with the last commit

//         if (changedFiles.files.length === 0) {
//             console.log("No changes detected in git diff after the pull.");
//         } else {
//             console.log("Changed files after the pull:", changedFiles.files.map(file => file.file)); // Log the changed files
//         }

//         return changedFiles.files.map(file => file.file);
//     } catch (error) {
//         console.error("Error checking git diff:", error);
//         throw error; // Rethrow the error to handle it in the calling function
//     }
// }

// module.exports = {
//     checkGitDiff
// };

// const simpleGit = require('simple-git');
// const path = require('path');

// const git = simpleGit(path.join(__dirname, '../cvelistV5')); // Adjust the path to your repo directory

// async function checkGitDiff() {
//     try {
//         // Fetch the latest changes from the remote repository
//         await git.fetch();

//         // Check if the local branch is behind the remote
//         const status = await git.status();
//         if (status.behind > 0) {
//             console.log(`Your branch is ${status.behind} commit(s) behind the remote. Pulling latest changes...`);

//             const pullResult = await git.pull();
//             console.log('Pulling the latest changes...');
//             console.log('Files updated in pull:', pullResult.files);  // Log which files were updated
//         } else {
//             console.log("Your branch is up to date with the remote.");
//         }

//         // Now check for git diff
//         const diffSummary = await git.diffSummary();
//         const changedFiles = diffSummary.files.map(file => file.file); // Get the file paths

//         if (changedFiles.length === 0) {
//             console.log("No changes detected in git diff after the pull.");
//         } else {
//             console.log("Changed files after the pull:", changedFiles); // Log the changed files
//         }

//         return changedFiles;
//     } catch (error) {
//         console.error("Error checking git diff:", error);
//         throw error; // Rethrow the error to handle it in the calling function
//     }
// }

// module.exports = {
//     checkGitDiff
// };






// const simpleGit = require('simple-git');
// const path = require('path');

// const git = simpleGit(path.join(__dirname, '../cvelistV5')); // Adjust the path to your repo directory

// async function checkGitDiff() {
//     try {
//         // Fetch the latest changes from the remote repository
//         await git.fetch();

//         // Check if the local branch is behind the remote
//         const status = await git.status();
//         if (status.behind > 0) {
//             console.log(`Your branch is ${status.behind} commit(s) behind the remote. Pulling latest changes...`);
//             await git.pull();
//         }

//         // Get the list of changed files since the last pull/commit
//         const diffSummary = await git.diffSummary();
//         const changedFiles = diffSummary.files.map(file => file.file); // Get the file paths

//         return changedFiles;
//     } catch (error) {
//         console.error("Error checking git diff:", error);
//         throw error; // Rethrow the error to handle it in the calling function
//     }
// }

// module.exports = {
//     checkGitDiff
// };




// const simpleGit = require('simple-git');
// const path = require('path');

// const git = simpleGit(path.join(__dirname, '../cvelistV5')); // Adjust the path to your repo directory

// async function checkGitDiff() {
//     try {
//         // Fetch the latest changes from the remote repository
//         await git.fetch();

//         // Get the list of changed files since the last commit
//         const status = await git.status();

//         // Filter and return files that are modified or added
//         const changedFiles = status.files
//             .filter(file => file.index !== '0' || file.working_dir !== '0') // modified or added files
//             .map(file => file.path); // Get the file paths

//         return changedFiles;
//     } catch (error) {
//         console.error("Error checking git diff:", error);
//         throw error; // Rethrow the error to handle it in the calling function
//     }
// }

// module.exports = {
//     checkGitDiff
// };
