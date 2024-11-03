const simpleGit = require('simple-git');
const fs = require('fs');
const path = require('path');

const repoPath = path.resolve(__dirname, '../../cvelistV5');  // Path to your local repository
const git = simpleGit(repoPath);

async function cloneOrPullRepo() {
    try {
        const isRepo = await git.checkIsRepo();

        if (!isRepo) {
            console.log('Cloning repository...');
            await git.clone('https://github.com/CVEProject/cvelistV5.git', repoPath);
        } else {
            console.log('Pulling the latest changes...');
            await git.pull();
        }
    } catch (error) {
        if (error.message.includes('cannot lock ref')) {
            console.error('Git lock error detected, attempting to resolve...');
            try {
                // Attempt to remove the lock file
                const lockFile = path.join(repoPath, '.git/refs/remotes/origin/main.lock');
                if (fs.existsSync(lockFile)) {
                    fs.unlinkSync(lockFile);
                    console.log('Removed stale lock file. Retrying pull...');
                    await git.pull();
                } else {
                    throw new Error('Lock file not found, manual intervention may be needed.');
                }
            } catch (lockError) {
                console.error('Failed to remove lock file:', lockError);
            }
        } else {
            console.error('Error pulling/cloning repository:', error);
        }
    }
}

module.exports = { cloneOrPullRepo };

// const simpleGit = require('simple-git');
// const path = require('path');
// const fs = require('fs');

// const GIT_REPO_URL = 'https://github.com/CVEProject/cvelistV5.git';
// const LOCAL_DIR = path.resolve(__dirname, '../cvelistV5');

// const git = simpleGit(LOCAL_DIR);

// async function cloneOrPullRepo() {
//     try {
//         // Check if the directory exists
//         if (fs.existsSync(LOCAL_DIR)) {
//             console.log(`Directory exists. Pulling updates from ${GIT_REPO_URL}...`);
//             await git.pull();  // Pull updates from the existing repo
//             console.log('Updates pulled successfully.');
//         } else {
//             console.log('Manually clone repo');
//             // console.log(`Cloning into '${LOCAL_DIR}'...`);
//             // await git.clone(GIT_REPO_URL, LOCAL_DIR);
//             // console.log('Repository cloned successfully.');
//         }
//     } catch (error) {
//         console.error('Error during GitHub clone/pull:', error);
//     }
// }

// module.exports = { cloneOrPullRepo };
