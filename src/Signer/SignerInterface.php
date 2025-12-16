<?php

namespace Jekka\Tiktok\Signer;

use Psr\Http\Message\RequestInterface;

interface SignerInterface
{
    public function sign(RequestInterface $request, array &$query): RequestInterface;
}
