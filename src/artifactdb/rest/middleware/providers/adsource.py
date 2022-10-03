
class AbstractActiveDirectorySource:

    async def get_ad_groups(self, user):
        raise NotImplementedError("Implement me in sub-class")

