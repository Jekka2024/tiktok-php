<?php

namespace Jekka2024\Tiktok\Signer;

use Psr\Http\Message\RequestInterface;

interface SignerInterface
{
    public function sign(RequestInterface $request, array &$query): RequestInterface;
}
