import { Box } from '@mui/material'
import Head from 'next/head'
import { FC } from 'react'

interface MetaTagsTypes {
  history: any[]
  createdBy: string
  name: string
  description: string
  price: string
  denom: string
  nftType: string
  dimensions: string
  royalty: string
  edition: string
  media: string
  createdAt: string
  recipeId: string
  src: string
  thumbnail: string
}
export const MetaTags: FC<MetaTagsTypes> = ({
  name,
  thumbnail,
  description,
  price,
  media
}) => {
  return (
    <Box data-testid="metaTags-molecule">
      <Head>
        <meta
          name="description"
          content={`${description}
        Price: ${
          price === undefined || price === 'undefined undefined'
            ? 'Free'
            : price
        }`}
        ></meta>
        <meta property="og:title" content={name} />
        <meta
          property="og:description"
          content={`${description}
        Price: ${
          price === undefined || price === 'undefined undefined'
            ? 'Free'
            : price
        }`}
          data-rh="true"
        />
        <meta property="og:url" content={thumbnail ?? media} />
        <meta property="og:image" content={thumbnail ?? media} />
        <meta property="og:image:width" content="1200" />
        <meta property="og:image:height" content="852.2222222222222" />
        <meta name="twitter:card" content="summary_large_image" />
        <meta name="twitter:title" content={name} />
        <meta
          name="twitter:description"
          content={`${description}
        Price: ${
          price === undefined || price === 'undefined undefined'
            ? 'Free'
            : price
        }`}
        ></meta>
      </Head>
    </Box>
  )
}