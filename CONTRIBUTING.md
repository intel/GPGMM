# How to Contribute to GPGMM

We'd love to accept your patches and contributions to this project. There are
just a few small guidelines you need to follow.

NOTE: If you are new to GitHub, please start by reading [Pull Request
howto](https://help.github.com/articles/about-pull-requests/)

## Guidelines for Pull Requests

*  All submissions, including submissions by project members, require review.
   We use GitHub pull requests for this purpose. Consult
   [GitHub Help](https://help.github.com/articles/about-pull-requests/) for more
   information on using pull requests.

*  Create **small PRs** that are narrowly focused on **addressing a single concern**.
   When PRs try to fix several things at a time, if only one fix is considered
   acceptable, nothing gets merged and both author's & review's time is wasted.
   Create more PRs to address different concerns and everyone will be happy.

*  Provide a good **PR description** as a record of **what** change is being
   made and **why** it was made. Link to a GitHub issue if it exists.

*  Don't fix code style and formatting unless you are already changing that line
   to address an issue. Formatting of modified lines may be done using
   `git clang-format`. PRs with irrelevant changes won't be merged. If you do
   want to fix formatting or style, do that in a separate PR.

*  Unless your PR is trivial, you should expect there will be reviewer comments
   that you'll need to address before merging. We expect you to be reasonably
   responsive to those comments, otherwise the PR will be closed after 2-3 weeks
   of inactivity.

*  Maintain **clean commit history** and use **meaningful commit messages**.
   PRs with messy commit history are difficult to review and won't be merged.
   Use `rebase -i upstream/main` to curate your commit history and/or to
   bring in latest changes from main (but avoid rebasing in the middle of a
   code review).

*  Keep your PR up to date with upstream/main (if there are merge conflicts,
   we can't really merge your change).

*  **All tests need to be passing** before your change can be merged. We
   recommend you **run tests locally** (see below)

*  Exceptions to the rules can be made if there's a compelling reason for doing
   so. That is - the rules are here to serve us, not the other way around, and
   the rules need to be serving their intended purpose to be valuable.
